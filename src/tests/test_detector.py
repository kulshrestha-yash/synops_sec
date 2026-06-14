"""Unit tests for adaptive threat detector with property-based testing."""

from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from detector.adaptive_detector import AdaptiveThreatDetector


@pytest.fixture
def mock_engine():
    """Mock temporal engine with fixed predictions."""
    engine = MagicMock()
    engine.predict_threat.return_value = {
        "threat_probability": 0.8,
        "is_threat": True,
        "confidence": 0.85,
    }
    return engine


@pytest.fixture
def mock_extractor():
    """Mock feature extractor with fixed outputs."""
    extractor = MagicMock()
    extractor.extract_temporal_features.return_value = {
        "shannon_entropy": 2.5,
        "burst_score": 5.0,
        "rare_event_ratio": 0.3,
        "repetition_score": 0.4,
        "event_density": 0.8,
    }
    extractor.calculate_anomaly_score.return_value = 0.4
    return extractor


@pytest.fixture
def detector(mock_engine, mock_extractor):
    """Create detector with mocked components."""
    return AdaptiveThreatDetector(
        temporal_engine=mock_engine,
        feature_extractor=mock_extractor,
        confidence_threshold=0.7,
        adaptation_rate=0.01,
    )


def test_ensemble_weighting(detector):
    """Test ensemble score calculation with 50/30/20 weights."""
    # Mock: lstm=0.8, behavior results in ~0.6, anomaly=0.4
    # Expected: 0.8*0.5 + 0.6*0.3 + 0.4*0.2 = 0.4 + 0.18 + 0.08 = 0.66
    
    result = detector.analyze_sequence(["open", "read", "write"])
    
    # Allow small floating point tolerance
    assert 0.65 <= result["threat_score"] <= 0.67, \
        f"Expected ~0.66, got {result['threat_score']}"
    assert result["lstm_confidence"] == 0.8
    assert result["anomaly_score"] == 0.4


def test_context_multiplier_privileged(detector):
    """Test privileged process context increases score by 1.2×."""
    result_no_context = detector.analyze_sequence(["open", "read", "write"])
    base_score = result_no_context["threat_score"]
    
    result_privileged = detector.analyze_sequence(
        ["open", "read", "write"],
        context={"privileged_process": True}
    )
    
    expected_score = min(base_score * 1.2, 1.0)
    assert abs(result_privileged["threat_score"] - expected_score) < 0.01


def test_context_multiplier_external(detector):
    """Test external connection context increases score by 1.15×."""
    result_no_context = detector.analyze_sequence(["socket", "connect"])
    base_score = result_no_context["threat_score"]
    
    result_external = detector.analyze_sequence(
        ["socket", "connect"],
        context={"external_connection": True}
    )
    
    expected_score = min(base_score * 1.15, 1.0)
    assert abs(result_external["threat_score"] - expected_score) < 0.01


def test_context_multiplier_known_good(detector):
    """Test known_good context decreases score by 0.5×."""
    result_no_context = detector.analyze_sequence(["open", "read"])
    base_score = result_no_context["threat_score"]
    
    result_known_good = detector.analyze_sequence(
        ["open", "read"],
        context={"known_good": True}
    )
    
    expected_score = base_score * 0.5
    assert abs(result_known_good["threat_score"] - expected_score) < 0.01


def test_action_threshold_critical(detector):
    """Test score ≥0.9 maps to CRITICAL/IMMEDIATE_ISOLATION."""
    detector.mock_engine.predict_threat.return_value = {
        "threat_probability": 1.0,
        "is_threat": True,
        "confidence": 1.0,
    }
    detector.mock_extractor.calculate_anomaly_score.return_value = 1.0
    
    result = detector.analyze_sequence(["encrypt", "inject", "hook"])
    
    assert result["severity"] == "CRITICAL"
    assert result["recommended_action"] == "IMMEDIATE_ISOLATION"


def test_action_threshold_high(mock_engine, mock_extractor):
    """Test score ≥0.8 maps to HIGH/SUSPEND_AND_ANALYZE."""
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.85,
        "is_threat": True,
        "confidence": 0.9,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.7
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    result = detector.analyze_sequence(["socket", "connect", "send"])
    
    assert result["severity"] == "HIGH"
    assert result["recommended_action"] == "SUSPEND_AND_ANALYZE"


def test_action_threshold_medium(mock_engine, mock_extractor):
    """Test score ≥0.7 maps to MEDIUM/ENHANCED_MONITORING."""
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.7,
        "is_threat": True,
        "confidence": 0.75,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.6
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    result = detector.analyze_sequence(["open", "write", "unlink"])
    
    assert result["severity"] == "MEDIUM"
    assert result["recommended_action"] == "ENHANCED_MONITORING"


def test_action_threshold_low(mock_engine, mock_extractor):
    """Test score <0.7 maps to LOW/CONTINUE_MONITORING."""
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.3,
        "is_threat": False,
        "confidence": 0.7,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.2
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    result = detector.analyze_sequence(["open", "read", "close"])
    
    assert result["severity"] == "LOW"
    assert result["recommended_action"] == "CONTINUE_MONITORING"


def test_threat_intelligence_tracking(detector):
    """Test that repeated signatures increase frequency."""
    sequence = ["open", "read", "encrypt", "write", "unlink"] * 2
    
    # Analyze same signature 3 times
    for _ in range(3):
        detector.analyze_sequence(sequence)
    
    # Check that signature was recorded
    assert len(detector.known_attack_signatures) == 1
    
    sig_data = list(detector.known_attack_signatures.values())[0]
    assert sig_data["frequency"] == 3
    assert len(sig_data["confidence_trend"]) == 3


def test_adaptation_after_100_predictions(mock_engine, mock_extractor):
    """Test threshold adaptation triggers after 100 predictions."""
    # Setup: recent predictions deviate significantly from historical
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.9,  # High threat
        "is_threat": True,
        "confidence": 0.95,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.8
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    initial_threshold = detector.confidence_threshold
    
    # Generate 100 high-threat predictions
    for _ in range(100):
        detector.analyze_sequence(["encrypt", "inject"])
    
    # Threshold should have adapted
    assert detector.confidence_threshold != initial_threshold


def test_false_positive_adjustment(detector):
    """Test that FP buffer triggers threshold increase."""
    initial_threshold = detector.confidence_threshold
    
    # Report 25 false positives
    for i in range(25):
        detector.report_false_positive([f"event_{i}"])
    
    assert detector.confidence_threshold > initial_threshold
    assert detector.detection_stats["false_positives"] == 25


def test_get_stats(detector):
    """Test statistics collection."""
    # Analyze some sequences
    for _ in range(10):
        detector.analyze_sequence(["open", "read", "write"])
    
    stats = detector.get_stats()
    
    assert stats["total_analyzed"] == 10
    assert stats["threats_detected"] >= 0
    assert 0 <= stats["detection_rate"] <= 1.0
    assert 0 <= stats["fp_rate"] <= 1.0


def test_export_threat_intelligence(detector, tmp_path):
    """Test threat intelligence JSON export."""
    # Generate some threat signatures
    for i in range(5):
        detector.analyze_sequence(["encrypt", f"event_{i}", "write"])
    
    export_path = tmp_path / "threat_intel.json"
    detector.export_threat_intelligence(export_path)
    
    assert export_path.exists()
    
    import json
    with export_path.open("r") as f:
        data = json.load(f)
    
    assert len(data) > 0
    for sig_hash, sig_data in data.items():
        assert "signature" in sig_data
        assert "frequency" in sig_data
        assert "avg_score" in sig_data
        assert "first_seen" in sig_data
        assert "last_seen" in sig_data
        assert "related_sequences" in sig_data
        assert "confidence_trend" in sig_data
        assert "recommended_action" in sig_data


@given(st.lists(st.text(min_size=1, max_size=20), min_size=10, max_size=50))
@settings(max_examples=30, deadline=None)
def test_property_threat_score_bounded(sequence):
    """Property test: threat scores should always be in [0, 1]."""
    mock_engine = MagicMock()
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.7,
        "is_threat": True,
        "confidence": 0.8,
    }
    
    mock_extractor = MagicMock()
    mock_extractor.extract_temporal_features.return_value = {
        "shannon_entropy": 2.0,
        "burst_score": 3.0,
        "rare_event_ratio": 0.2,
        "repetition_score": 0.3,
        "event_density": 0.5,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.5
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    result = detector.analyze_sequence(sequence)
    
    assert 0 <= result["threat_score"] <= 1.0, \
        f"Threat score {result['threat_score']} out of bounds"


@given(st.lists(st.sampled_from(["open", "read", "write", "encrypt"]), 
                min_size=10, max_size=50))
@settings(max_examples=30, deadline=None)
def test_property_valid_actions(sequence):
    """Property test: recommended actions should be from valid set."""
    mock_engine = MagicMock()
    mock_engine.predict_threat.return_value = {
        "threat_probability": 0.6,
        "is_threat": True,
        "confidence": 0.7,
    }
    
    mock_extractor = MagicMock()
    mock_extractor.extract_temporal_features.return_value = {
        "shannon_entropy": 2.0,
        "burst_score": 3.0,
        "rare_event_ratio": 0.2,
        "repetition_score": 0.3,
        "event_density": 0.5,
    }
    mock_extractor.calculate_anomaly_score.return_value = 0.4
    
    detector = AdaptiveThreatDetector(mock_engine, mock_extractor)
    result = detector.analyze_sequence(sequence)
    
    valid_actions = {
        "IMMEDIATE_ISOLATION",
        "SUSPEND_AND_ANALYZE",
        "ENHANCED_MONITORING",
        "CONTINUE_MONITORING",
    }
    
    assert result["recommended_action"] in valid_actions

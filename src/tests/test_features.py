"""Unit tests for behavioral feature extraction with property-based testing."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from features.behavioral_features import BehavioralFeatureExtractor


@pytest.fixture
def extractor():
    """Create fresh extractor for each test."""
    return BehavioralFeatureExtractor(window_size=100)


@pytest.fixture
def normal_sequence():
    """Typical benign syscall sequence."""
    return ["open", "read", "write", "close"] * 10


@pytest.fixture
def malware_sequence():
    """Suspicious syscall sequence with rare events."""
    return ["open", "read", "encrypt", "write", "unlink"] * 8


def test_extract_temporal_features_keys(extractor, normal_sequence):
    """Test that all expected feature keys are present."""
    features = extractor.extract_temporal_features(normal_sequence)
    
    expected_keys = {
        "shannon_entropy",
        "burst_score",
        "rare_event_ratio",
        "repetition_score",
        "event_density",
    }
    
    assert set(features.keys()) == expected_keys


def test_extract_temporal_features_bounded(extractor, normal_sequence):
    """Test that feature values are in reasonable ranges."""
    features = extractor.extract_temporal_features(normal_sequence)
    
    # All features should be non-negative
    for key, value in features.items():
        assert value >= 0, f"{key} is negative: {value}"
    
    # Entropy bounded by log2 of unique events
    assert features["shannon_entropy"] <= 10, "Entropy unexpectedly high"
    
    # Ratios should be in [0, 1]
    assert features["rare_event_ratio"] <= 1.0
    assert features["repetition_score"] <= 1.0


def test_entropy_calculation(extractor):
    """Test entropy reflects distribution uniformity."""
    # Uniform distribution should have higher entropy
    uniform_seq = ["open", "read", "write", "close", "fork", "exec"] * 5
    uniform_features = extractor.extract_temporal_features(uniform_seq)
    
    # Single repeated event should have low entropy
    repeated_seq = ["open"] * 30
    repeated_features = extractor.extract_temporal_features(repeated_seq)
    
    assert uniform_features["shannon_entropy"] > repeated_features["shannon_entropy"]


def test_rare_event_detection(extractor):
    """Test that suspicious events increase rare_event_ratio."""
    normal_seq = ["open", "read", "write", "close"] * 10
    suspicious_seq = ["open", "encrypt", "inject", "hook", "pack"] * 8
    
    normal_features = extractor.extract_temporal_features(normal_seq)
    suspicious_features = extractor.extract_temporal_features(suspicious_seq)
    
    assert normal_features["rare_event_ratio"] == 0.0
    assert suspicious_features["rare_event_ratio"] > 0.5


def test_update_baseline(extractor):
    """Test baseline creation from normal sequences."""
    normal_sequences = [
        ["open", "read", "write", "close"] * 10,
        ["socket", "bind", "listen", "accept"] * 10,
        ["fork", "execve", "wait", "exit"] * 10,
    ]
    
    baseline = extractor.update_baseline(normal_sequences, duration_minutes=10)
    
    required_keys = {
        "avg_entropy", "std_entropy",
        "avg_burst", "std_burst",
        "avg_event_rate",
        "avg_event_density", "std_event_density",
    }
    
    assert set(baseline.keys()) == required_keys
    assert all(v >= 0 for v in baseline.values())


def test_calculate_anomaly_score_normal(extractor, normal_sequence):
    """Test that normal sequences have low anomaly scores."""
    # Train baseline on normal data
    normal_sequences = [["open", "read", "write", "close"] * 10] * 5
    extractor.update_baseline(normal_sequences, duration_minutes=10)
    
    # Test similar normal sequence
    anomaly_score = extractor.calculate_anomaly_score(normal_sequence)
    
    assert 0 <= anomaly_score <= 1.0
    assert anomaly_score < 0.3, f"Normal sequence scored too high: {anomaly_score}"


def test_calculate_anomaly_score_malware(extractor, malware_sequence):
    """Test that malware sequences have high anomaly scores."""
    # Train baseline on normal data
    normal_sequences = [["open", "read", "write", "close"] * 10] * 5
    extractor.update_baseline(normal_sequences, duration_minutes=10)
    
    # Test malware sequence
    anomaly_score = extractor.calculate_anomaly_score(malware_sequence)
    
    assert 0 <= anomaly_score <= 1.0
    assert anomaly_score > 0.5, f"Malware sequence scored too low: {anomaly_score}"


def test_extract_network_features(extractor):
    """Test network feature extraction from packet data."""
    packets = [
        {"destination_port": 80, "payload_size": 1500, "timestamp": 1.0},
        {"destination_port": 443, "payload_size": 1200, "timestamp": 2.0},
        {"destination_port": 4444, "payload_size": 500, "timestamp": 3.0},
    ]
    
    features = extractor.extract_network_features(packets)
    
    assert "unique_destination_ports" in features
    assert "suspicious_port_hits" in features
    assert "avg_payload_size" in features
    assert "payload_size_variance" in features
    assert "beaconing_score" in features
    
    assert features["unique_destination_ports"] == 3.0
    assert features["suspicious_port_hits"] == 1.0  # port 4444


def test_baseline_required_for_anomaly(extractor, normal_sequence):
    """Test that anomaly calculation requires baseline."""
    with pytest.raises(ValueError, match="Baseline is not set"):
        extractor.calculate_anomaly_score(normal_sequence)


@given(st.lists(st.sampled_from(["open", "read", "write", "close", "fork", "exec"]), 
                min_size=10, max_size=100))
@settings(max_examples=50, deadline=None)
def test_property_features_bounded(sequence):
    """Property test: all features should be in valid ranges."""
    extractor = BehavioralFeatureExtractor()
    features = extractor.extract_temporal_features(sequence)
    
    # All features non-negative
    for key, value in features.items():
        assert value >= 0, f"{key} is negative"
    
    # Specific bounds
    assert features["rare_event_ratio"] <= 1.0
    assert features["repetition_score"] <= 1.0
    assert features["event_density"] <= 10.0  # reasonable upper bound


@given(st.lists(st.sampled_from(["open", "read", "write", "close"]), 
                min_size=10, max_size=100))
@settings(max_examples=30, deadline=None)
def test_property_anomaly_bounded(sequence):
    """Property test: anomaly scores should be in [0, 1] after baseline."""
    extractor = BehavioralFeatureExtractor()
    
    # Create baseline
    baseline_sequences = [["open", "read", "write", "close"] * 10] * 3
    extractor.update_baseline(baseline_sequences, duration_minutes=10)
    
    # Calculate anomaly
    anomaly_score = extractor.calculate_anomaly_score(sequence)
    
    assert 0 <= anomaly_score <= 1.0, \
        f"Anomaly score {anomaly_score} out of bounds"


@given(st.lists(st.text(min_size=1, max_size=20), min_size=10, max_size=100))
@settings(max_examples=30, deadline=None)
def test_property_no_crashes(sequence):
    """Property test: feature extraction should never crash on valid sequences."""
    extractor = BehavioralFeatureExtractor()
    
    try:
        features = extractor.extract_temporal_features(sequence)
        assert isinstance(features, dict)
        assert len(features) == 5
    except Exception as e:
        pytest.fail(f"Feature extraction crashed on valid input: {e}")

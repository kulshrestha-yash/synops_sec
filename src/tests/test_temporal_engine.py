"""Unit tests for temporal pattern engine with property-based testing."""

import tempfile
from pathlib import Path

import numpy as np
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from neuromorphic.temporal_engine import TemporalPatternEngine


@pytest.fixture
def engine():
    """Create fresh engine for each test."""
    return TemporalPatternEngine()


@pytest.fixture
def sample_sequences():
    """Sample syscall sequences for testing."""
    return [
        ["open", "read", "write", "close"],
        ["socket", "bind", "listen", "accept"],
        ["fork", "execve", "wait", "exit"],
    ]


def test_build_model(engine):
    """Test model compilation and architecture."""
    model = engine.build_model(n_classes=2)
    
    assert model is not None
    assert len(model.layers) > 0
    assert model.output_shape == (None, 2)
    assert model.optimizer is not None


def test_preprocess_sequences_fit(engine, sample_sequences, tmp_path):
    """Test preprocessing with encoder fitting."""
    engine.models_dir = tmp_path
    engine.encoder_path = tmp_path / "label_encoder.pkl"
    
    X = engine.preprocess_sequences(sample_sequences, fit=True)
    
    assert X.shape[0] == len(sample_sequences)
    assert X.shape[1] == 50  # sequence_length
    assert engine.encoder_path.exists()
    assert hasattr(engine.label_encoder, "classes_")


def test_preprocess_sequences_transform(engine, sample_sequences, tmp_path):
    """Test preprocessing with encoder loading."""
    engine.models_dir = tmp_path
    engine.encoder_path = tmp_path / "label_encoder.pkl"
    
    # Fit first
    engine.preprocess_sequences(sample_sequences, fit=True)
    
    # Create new engine and transform
    engine2 = TemporalPatternEngine()
    engine2.models_dir = tmp_path
    engine2.encoder_path = tmp_path / "label_encoder.pkl"
    
    X = engine2.preprocess_sequences(sample_sequences, fit=False)
    
    assert X.shape[0] == len(sample_sequences)
    assert X.shape[1] == 50


def test_padding_and_truncation(engine, tmp_path):
    """Test sequence padding and truncation to fixed length."""
    engine.models_dir = tmp_path
    engine.encoder_path = tmp_path / "label_encoder.pkl"
    
    short_seq = [["open", "close"]]
    long_seq = [["open"] * 100]
    
    X_short = engine.preprocess_sequences(short_seq, fit=True)
    X_long = engine.preprocess_sequences(long_seq, fit=False)
    
    assert X_short.shape[1] == 50  # padded to 50
    assert X_long.shape[1] == 50   # truncated to 50


def test_predict_threat(engine, sample_sequences, tmp_path):
    """Test threat prediction output format."""
    engine.models_dir = tmp_path
    engine.encoder_path = tmp_path / "label_encoder.pkl"
    
    # Preprocess and build model
    X = engine.preprocess_sequences(sample_sequences, fit=True)
    engine.build_model(n_classes=2)
    
    # Predict on single sequence
    result = engine.predict_threat(sample_sequences[0])
    
    assert "threat_probability" in result
    assert "is_threat" in result
    assert "confidence" in result
    assert 0 <= result["threat_probability"] <= 1
    assert 0 <= result["confidence"] <= 1
    assert isinstance(result["is_threat"], bool)


def test_save_and_load(engine, sample_sequences, tmp_path):
    """Test model persistence and loading."""
    engine.models_dir = tmp_path
    engine.encoder_path = tmp_path / "label_encoder.pkl"
    
    # Build, train briefly, and save
    X = engine.preprocess_sequences(sample_sequences, fit=True)
    engine.build_model(n_classes=2)
    
    model_path = tmp_path / "test_model.h5"
    engine.save(model_path)
    
    assert model_path.exists()
    assert engine.encoder_path.exists()
    
    # Load in new engine
    engine2 = TemporalPatternEngine()
    engine2.models_dir = tmp_path
    engine2.encoder_path = tmp_path / "label_encoder.pkl"
    engine2.load(model_path)
    
    assert engine2.model is not None
    assert hasattr(engine2.label_encoder, "classes_")


@given(st.lists(st.text(min_size=1, max_size=20), min_size=1, max_size=100))
@settings(max_examples=50, deadline=None)
def test_property_no_crashes(sequence):
    """Property test: preprocessing should never crash on valid text sequences."""
    engine = TemporalPatternEngine()
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine.models_dir = Path(tmp_dir)
        engine.encoder_path = engine.models_dir / "label_encoder.pkl"
        
        try:
            X = engine.preprocess_sequences([sequence], fit=True)
            assert X.shape[0] == 1
            assert X.shape[1] == 50
        except Exception as e:
            pytest.fail(f"Preprocessing crashed on valid input: {e}")


@given(st.lists(st.sampled_from(["open", "read", "write", "close", "fork", "execve"]), 
                min_size=10, max_size=50))
@settings(max_examples=30, deadline=None)
def test_property_predictions_bounded(sequence):
    """Property test: all predictions should be in [0, 1] range."""
    engine = TemporalPatternEngine()
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine.models_dir = Path(tmp_dir)
        engine.encoder_path = engine.models_dir / "label_encoder.pkl"
        
        X = engine.preprocess_sequences([sequence], fit=True)
        engine.build_model(n_classes=2)
        
        result = engine.predict_threat(sequence)
        
        assert 0 <= result["threat_probability"] <= 1, \
            f"threat_probability {result['threat_probability']} out of bounds"
        assert 0 <= result["confidence"] <= 1, \
            f"confidence {result['confidence']} out of bounds"

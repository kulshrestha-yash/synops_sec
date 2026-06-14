"""Integration helper for neuromorphic threat detection system.

Provides simple API for loading trained models and analyzing syscall sequences.
Designed for easy integration by Person 2 into backend systems.

Example usage:
    >>> from integration_helper import load_production_model, create_detector_from_model
    >>> engine = load_production_model()
    >>> detector = create_detector_from_model(engine)
    >>> result = detector.analyze_sequence(["open", "read", "encrypt", "write"])
    >>> print(result["threat_score"], result["recommended_action"])

API Summary:
    load_production_model() -> TemporalPatternEngine
        Loads trained model and label encoder from models/ directory.
        
    create_detector_from_model(engine, baseline_path) -> AdaptiveThreatDetector
        Creates configured detector with behavioral features and baseline.
        
    quick_analyze(sequence_list, detector=None) -> list[dict]
        One-liner analysis for batch processing. Auto-loads model if needed.
"""

import json
from pathlib import Path
from typing import Any

from detector.adaptive_detector import AdaptiveThreatDetector
from features.behavioral_features import BehavioralFeatureExtractor
from neuromorphic.temporal_engine import TemporalPatternEngine

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_project_path(path: str | Path) -> Path:
    """Resolve artifact paths from cwd, project root, or src/."""

    candidate = Path(path)
    if candidate.is_absolute() or candidate.exists():
        return candidate

    root_candidate = PROJECT_ROOT / candidate
    if root_candidate.exists():
        return root_candidate

    src_candidate = PROJECT_ROOT / "src" / candidate
    if src_candidate.exists():
        return src_candidate

    return root_candidate


def load_production_model(
    model_path: str | Path = "models/temporal_engine.h5",
    encoder_path: str | Path = "models/label_encoder.pkl",
) -> TemporalPatternEngine:
    """Load trained temporal pattern engine with label encoder.
    
    Args:
        model_path: Path to trained .h5 model file.
        encoder_path: Path to pickled label encoder.
    
    Returns:
        Configured TemporalPatternEngine ready for inference.
    
    Raises:
        FileNotFoundError: If model files are missing. Run train_model.py first.
    """
    model_path = _resolve_project_path(model_path)
    encoder_path = _resolve_project_path(encoder_path)
    
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found at {model_path}. "
            "Run train_model.py to train the model first."
        )
    
    if not encoder_path.exists():
        raise FileNotFoundError(
            f"Label encoder not found at {encoder_path}. "
            "Run train_model.py to generate encoder."
        )
    
    engine = TemporalPatternEngine(models_dir=model_path.parent)
    engine.encoder_path = encoder_path
    engine.load(model_path)
    
    return engine


def create_detector_from_model(
    engine: TemporalPatternEngine,
    baseline_path: str | Path = "models/detector_baseline.json",
) -> AdaptiveThreatDetector:
    """Create adaptive detector with behavioral baseline.
    
    Args:
        engine: Loaded TemporalPatternEngine.
        baseline_path: Path to behavioral baseline JSON.
    
    Returns:
        Configured AdaptiveThreatDetector ready for analysis.
    
    Raises:
        FileNotFoundError: If baseline file is missing.
    """
    baseline_path = _resolve_project_path(baseline_path)
    
    if not baseline_path.exists():
        raise FileNotFoundError(
            f"Baseline not found at {baseline_path}. "
            "Run train_model.py to generate baseline."
        )
    
    with baseline_path.open("r") as f:
        baseline = json.load(f)
    
    feature_extractor = BehavioralFeatureExtractor()
    feature_extractor.baseline = baseline
    
    detector = AdaptiveThreatDetector(
        temporal_engine=engine,
        feature_extractor=feature_extractor,
        confidence_threshold=0.7,
        adaptation_rate=0.01,
    )
    
    return detector


def quick_analyze(
    sequence_list: list[list[str]],
    detector: AdaptiveThreatDetector | None = None,
) -> list[dict[str, Any]]:
    """Analyze multiple sequences with one function call.
    
    Args:
        sequence_list: List of syscall sequences to analyze.
        detector: Optional pre-configured detector. Auto-loads if None.
    
    Returns:
        List of analysis results, one per sequence.
    """
    if detector is None:
        engine = load_production_model()
        detector = create_detector_from_model(engine)
    
    results = []
    for sequence in sequence_list:
        result = detector.analyze_sequence(sequence)
        results.append(result)
    
    return results

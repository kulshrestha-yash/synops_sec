# Neuromorphic Threat Detector

BiLSTM-based threat detection system with ensemble scoring, adaptive thresholding, and behavioral feature extraction.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Train Model
```bash
python train_model.py
```
This will:
- Load synthetic data (500 normal, 100 malware sequences)
- Train BiLSTM model for 30 epochs
- Save model to `models/temporal_engine.h5`
- Create baseline to `models/detector_baseline.json`
- Print metrics and warnings if below targets

### 3. Run Tests
```bash
pytest tests/ -v
```
Includes unit tests and hypothesis property-based tests for:
- Temporal pattern engine
- Behavioral features
- Adaptive detector

### 4. Run Integration Demo
```bash
python main.py
```
Demonstrates full pipeline:
- Load model → Analyze sequences → Trigger responder → Export threat intel

### 5. Validate Model (Optional)
```bash
python validate_model.py
```
Generates comprehensive performance report to `docs/validation_report.txt`

### 6. Optimize Model (Optional)
```bash
python optimize_model.py
```
Applies quantization and pruning. Benchmarks inference time and accuracy.

## Project Structure

```
src/
├── data/                      # Synthetic training data
│   ├── normal_sequences.pkl
│   └── malware_sequences.pkl
├── models/                    # Trained models (created after training)
│   ├── temporal_engine.h5
│   ├── label_encoder.pkl
│   └── detector_baseline.json
├── neuromorphic/              # Core ML components
│   └── temporal_engine.py
├── features/                  # Feature extraction
│   └── behavioral_features.py
├── detector/                  # Adaptive detection
│   └── adaptive_detector.py
├── responder/                 # Mock security responses
│   └── mock_responder.py
├── tests/                     # Unit + property tests
│   ├── test_temporal_engine.py
│   ├── test_features.py
│   └── test_detector.py
├── docs/                      # Documentation
│   └── MODEL.md
├── train_model.py             # Training pipeline
├── main.py                    # Integration demo
├── validate_model.py          # Model validation
├── optimize_model.py          # Model optimization
└── integration_helper.py      # API for backend integration
```

## API Usage (for Person 2)

```python
from integration_helper import load_production_model, create_detector_from_model

# Load model
engine = load_production_model()
detector = create_detector_from_model(engine)

# Analyze sequence
result = detector.analyze_sequence(["open", "read", "encrypt", "write"])

print(result["threat_score"])          # 0.87
print(result["recommended_action"])    # "SUSPEND_AND_ANALYZE"
print(result["severity"])              # "HIGH"

# Get statistics
stats = detector.get_stats()
print(stats["detection_rate"])

# Export threat intelligence
detector.export_threat_intelligence("threat_intel.json")
```

## Key Features

- **Ensemble Detection**: LSTM (50%) + Behavioral (30%) + Anomaly (20%)
- **Context-Aware**: Adjusts scores based on privileged processes, external connections
- **Adaptive Thresholding**: Auto-adjusts detection threshold based on recent predictions
- **Rich Threat Intelligence**: Tracks signatures with frequency, confidence trends, related sequences
- **Mock Responder**: Dry-run mode for testing detection → response pipeline
- **Property-Based Tests**: Hypothesis library for automatic edge case discovery

## Targets

| Metric | Target | Status |
|--------|--------|--------|
| Accuracy | >85% | See training output |
| Precision | >80% | See training output |
| Recall | >75% | See training output |
| Inference | <100ms | See validation report |

## Documentation

- **Architecture & API**: `docs/MODEL.md`
- **Validation Report**: `docs/validation_report.txt` (generated after validation)
- **Code Documentation**: Inline docstrings in all modules

## Next Steps

1. Run training pipeline: `python train_model.py`
2. Review MODEL.md for architecture details
3. Run tests: `pytest tests/ -v`
4. Run demo: `python main.py`
5. For backend integration, see `integration_helper.py`

## Handoff Notes for Person 2

- All models saved to `models/` directory
- Use `integration_helper.py` for easy model loading
- Replace `MockResponder` with real security controls
- API documented in `docs/MODEL.md`
- Monitor detection stats with `detector.get_stats()`

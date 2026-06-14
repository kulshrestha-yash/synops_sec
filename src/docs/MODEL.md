# Neuromorphic Threat Detection Model

## Architecture

```
Input: Syscall Sequence (variable length)
    ↓
┌───────────────────────────────────────────────┐
│ Embedding Layer (vocab=100 → dim=64)         │
│ Maps syscall tokens to dense vectors         │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Bidirectional LSTM (128 units)               │
│ Return sequences for temporal context        │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dropout (0.3) - Regularization               │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Bidirectional LSTM (64 units)                │
│ Return sequences for deeper patterns         │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dropout (0.3)                                 │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ LSTM (32 units) - Sequence aggregation        │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dropout (0.3)                                 │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dense (64 units, ReLU)                        │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dropout (0.2)                                 │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Dense (32 units, ReLU)                        │
└───────────────────────────────────────────────┘
    ↓
┌───────────────────────────────────────────────┐
│ Output Dense (2 units, Softmax)               │
│ Class probabilities: [Normal, Threat]        │
└───────────────────────────────────────────────┘
```

### Ensemble Detection Pipeline

```
Syscall Sequence
    ↓
    ├─→ [Temporal Engine] ──→ LSTM Confidence (50%)
    ├─→ [Behavioral Features] ──→ Behavior Score (30%)
    └─→ [Anomaly Detector] ──→ Anomaly Score (20%)
            ↓
    Weighted Ensemble Score
            ↓
    Context Multipliers (optional)
            ↓
    Threat Decision + Recommended Action
```

## BiLSTM Rationale: Neuromorphic Inspiration

The model uses Long Short-Term Memory (LSTM) networks inspired by biological memory mechanisms:

- **LSTM Gates as Biological Memory**: LSTM cells contain three gates (forget, input, output) that decide what information to retain, update, or forget. This mimics how biological neurons consolidate important signals while suppressing noise—a simplified analog of memory formation in the brain.

- **Bidirectional Processing**: Each BiLSTM layer processes syscall sequences in both forward and backward directions, resembling parallel neural pathways that integrate temporal context from both past and future events before making classification decisions.

- **Stacked Architecture**: Multiple LSTM layers create a hierarchical temporal feature detector, similar to how biological sensory systems build increasingly abstract representations through cortical layers.

This neuromorphic design helps the model learn complex temporal patterns characteristic of malware behavior (e.g., code injection sequences, encryption loops) that simpler models might miss.

## Behavioral Features

The system extracts five behavioral features that highlight malware-specific patterns:

### 1. **Shannon Entropy**
- **What**: Measures randomness/predictability of syscall distribution
- **Malware Indicator**: **Polymorphic or obfuscated malware** produces higher entropy because it uses varied, unpredictable syscall patterns to evade signature-based detection
- **Range**: 0 (single repeated call) to ~5+ (uniform distribution)

### 2. **Burst Score**
- **What**: Standard deviation of activity across sliding windows
- **Malware Indicator**: **Ransomware encryption loops** or **code injection attacks** produce intense bursts of activity followed by quieter periods, unlike steady benign processes
- **Range**: 0 (constant rate) to 10+ (highly bursty)

### 3. **Rare Event Ratio**
- **What**: Frequency of suspicious syscalls (`encrypt`, `inject`, `hook`, `pack`, `obfuscate`)
- **Malware Indicator**: These calls are uncommon in benign programs but appear frequently in **malware tooling**, **payload setup**, and **anti-analysis techniques**
- **Range**: 0.0 (none) to 1.0 (all suspicious)

### 4. **Repetition Score**
- **What**: Proportion of repeated 3-grams (trigrams) in the sequence
- **Malware Indicator**: **Tight behavioral loops** like repeated read-transform-write cycles during **file encryption** or memory scanning produce high repetition
- **Range**: 0.0 (all unique) to 1.0 (fully repetitive)

### 5. **Event Density**
- **What**: Total events per time window
- **Malware Indicator**: **Automated malware** performs many actions rapidly (scanning, exfiltration) compared to slower **human-driven interactions**
- **Range**: 0.0 to 1.0+ (normalized by window size)

### Network Features (when available)

- **Suspicious Port Hits**: Connections to ports commonly used by backdoors (4444, 5555, 6666, 31337)
- **Beaconing Score**: Regularity of connection intervals—**command-and-control (C2) beacons** have machine-like timing
- **Payload Variance**: Mixed payload sizes suggest **staged data exfiltration** or binary transfers

## Training Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Epochs** | 30 | Early stopping with patience=5 prevents overfitting |
| **Batch Size** | 32 | Balances gradient stability and memory efficiency |
| **Optimizer** | Adam | Adaptive learning rate handles sparse syscall vocabulary |
| **Loss** | Categorical Crossentropy | Standard for binary classification (normal/threat) |
| **Validation Split** | 20% | Held-out data for unbiased evaluation |
| **Sequence Length** | 50 | Fixed padding/truncation captures typical attack patterns |
| **Embedding Dim** | 64 | Sufficient for ~50-100 unique syscalls |

### Regularization
- **Dropout**: 0.3 after LSTM layers, 0.2 after Dense layers
- **EarlyStopping**: Monitors validation loss, restores best weights

## Target Metrics

| Metric | Target | Achieved | Status |
|--------|--------|----------|--------|
| **Accuracy** | >85% | *(See training output)* | ✓/✗ |
| **Precision** | >80% | *(See training output)* | ✓/✗ |
| **Recall** | >75% | *(See training output)* | ✓/✗ |

**Precision** prioritizes reducing false positives (benign flagged as threat).  
**Recall** prioritizes catching real threats (malware not missed).

The 75% recall target accepts some false negatives to avoid alert fatigue from false positives.

## API Reference

### TemporalPatternEngine

```python
from neuromorphic.temporal_engine import TemporalPatternEngine

engine = TemporalPatternEngine()

# Build model
engine.build_model(n_classes=2)

# Preprocess sequences
X = engine.preprocess_sequences(sequences, fit=True)  # fit=True to train encoder

# Predict threat
result = engine.predict_threat(["open", "read", "encrypt", "write"])
# Returns: {"threat_probability": 0.87, "is_threat": True, "confidence": 0.92}

# Save/load
engine.save("models/temporal_engine.h5")
engine.load("models/temporal_engine.h5")
```

### BehavioralFeatureExtractor

```python
from features.behavioral_features import BehavioralFeatureExtractor

extractor = BehavioralFeatureExtractor(window_size=100)

# Extract features
features = extractor.extract_temporal_features(sequence)
# Returns: {"shannon_entropy": 2.3, "burst_score": 4.1, ...}

# Create baseline
baseline = extractor.update_baseline(normal_sequences, duration_minutes=10)

# Calculate anomaly
anomaly_score = extractor.calculate_anomaly_score(suspicious_sequence)
```

### AdaptiveThreatDetector

```python
from detector.adaptive_detector import AdaptiveThreatDetector

detector = AdaptiveThreatDetector(
    temporal_engine=engine,
    feature_extractor=extractor,
    confidence_threshold=0.7,
    adaptation_rate=0.01
)

# Analyze sequence
result = detector.analyze_sequence(
    event_sequence=["socket", "connect", "send", "recv"],
    context={"privileged_process": True}  # optional context
)
# Returns: {
#   "timestamp": "2026-06-13T21:00:00",
#   "threat_score": 0.82,
#   "is_threat": True,
#   "lstm_confidence": 0.78,
#   "anomaly_score": 0.65,
#   "behavioral_features": {...},
#   "recommended_action": "SUSPEND_AND_ANALYZE",
#   "severity": "HIGH"
# }

# Get statistics
stats = detector.get_stats()
# Returns: {"total_analyzed": 1500, "threats_detected": 120, ...}

# Export threat intelligence
detector.export_threat_intelligence("threat_intel.json")
```

### Integration Helper (for Person 2)

```python
from integration_helper import load_production_model, create_detector_from_model

# Load trained model
engine = load_production_model()

# Create detector with baseline
detector = create_detector_from_model(engine)

# Analyze sequences
result = detector.analyze_sequence(sequence)
```

## Limitations

1. **Requires Baseline**: Anomaly detection needs training on normal behavior. New deployments must collect benign data first.

2. **Synthetic Training Data**: Model trained on generated syscall patterns. Real-world malware may use different sequences. Continuous retraining recommended.

3. **Static Ensemble Weights**: 50/30/20 weights are fixed. Dynamic weight adjustment based on component performance could improve accuracy.

4. **Fixed Sequence Length**: 50-token padding/truncation may lose information from very long attack chains or compress short bursts.

5. **No Real-Time Learning**: Model doesn't update weights online. Detected threats are logged but don't immediately improve detection.

6. **Context Limited**: Context multipliers (privileged process, external connection) are manual flags. Automated context extraction from system state would be more robust.

## Future Work

### Short-Term Improvements
- **Attention Mechanisms**: Add multi-head attention after BiLSTM layers to focus on critical syscall subsequences
- **Data Augmentation**: Noise injection, sequence reversal, time-warping to improve robustness
- **Real Syscall Datasets**: Train on labeled traces from sandboxed malware samples (e.g., Cuckoo Sandbox logs)

### Medium-Term Enhancements
- **Online Learning**: Incremental model updates from confirmed true/false positives
- **Dynamic Ensemble Weights**: Meta-learner that adjusts LSTM/behavioral/anomaly weights based on recent performance
- **Multi-Modal Features**: Incorporate network traffic, file I/O metadata, process genealogy

### Long-Term Research
- **Graph Neural Networks**: Model inter-process relationships and system-wide attack graphs
- **Spiking Neural Networks**: True neuromorphic hardware implementation for edge deployment
- **Adversarial Robustness**: Defend against malware designed to evade ML detection

## References

- LSTM architecture inspired by Hochreiter & Schmidhuber (1997)
- Behavioral feature design based on malware analysis literature (Kolbitsch et al., 2009)
- Ensemble methods follow standard ML best practices (Dietterich, 2000)

---

**Model Version**: 1.0  
**Last Updated**: 2026-06-13  
**Maintainer**: Person 1 → Person 2 (backend integration)

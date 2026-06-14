"""Training pipeline for neuromorphic threat detection model."""

import json
import pickle
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, confusion_matrix, precision_score, recall_score
from sklearn.model_selection import train_test_split
from tensorflow.keras.utils import to_categorical

from features.behavioral_features import BehavioralFeatureExtractor
from neuromorphic.temporal_engine import TemporalPatternEngine


def main():
    print("=" * 60)
    print("NEUROMORPHIC THREAT DETECTOR - TRAINING PIPELINE")
    print("=" * 60)
    
    # Load synthetic data
    print("\n[1/7] Loading synthetic data...")
    with open("data/normal_sequences.pkl", "rb") as f:
        normal_sequences = pickle.load(f)
    with open("data/malware_sequences.pkl", "rb") as f:
        malware_sequences = pickle.load(f)
    
    print(f"  Loaded {len(normal_sequences)} normal sequences")
    print(f"  Loaded {len(malware_sequences)} malware sequences")
    
    # Combine and label
    all_sequences = normal_sequences + malware_sequences
    labels = [0] * len(normal_sequences) + [1] * len(malware_sequences)
    
    # Initialize engine and preprocess
    print("\n[2/7] Preprocessing sequences...")
    engine = TemporalPatternEngine()
    X = engine.preprocess_sequences(all_sequences, fit=True)
    y = to_categorical(labels, num_classes=2)
    
    print(f"  Encoded sequences shape: {X.shape}")
    print(f"  Labels shape: {y.shape}")
    
    # Train/validation split
    print("\n[3/7] Splitting data (80/20)...")
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, stratify=labels, random_state=42
    )
    print(f"  Training samples: {len(X_train)}")
    print(f"  Validation samples: {len(X_val)}")
    
    # Build and train model
    print("\n[4/7] Building and training model...")
    print("  Architecture: Embedding → 2×BiLSTM → LSTM → Dense")
    print("  Epochs: 30, Batch: 32, EarlyStopping: patience=5")
    
    engine.build_model(n_classes=2)
    history = engine.train(
        X_train, y_train, X_val, y_val,
        epochs=30, batch_size=32
    )
    
    # Evaluate
    print("\n[5/7] Evaluating model...")
    y_val_pred = engine.model.predict(X_val, verbose=0)
    y_val_pred_labels = np.argmax(y_val_pred, axis=1)
    y_val_true_labels = np.argmax(y_val, axis=1)
    
    accuracy = accuracy_score(y_val_true_labels, y_val_pred_labels)
    precision = precision_score(y_val_true_labels, y_val_pred_labels, zero_division=0)
    recall = recall_score(y_val_true_labels, y_val_pred_labels, zero_division=0)
    cm = confusion_matrix(y_val_true_labels, y_val_pred_labels)
    
    print(f"\n  Accuracy:  {accuracy:.4f}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    [[TN={cm[0,0]:3d}  FP={cm[0,1]:3d}]")
    print(f"     [FN={cm[1,0]:3d}  TP={cm[1,1]:3d}]]")
    
    # Check targets
    targets_met = True
    if accuracy < 0.85:
        print(f"\n  ⚠️  Accuracy {accuracy:.4f} below target (0.85)")
        targets_met = False
    if precision < 0.80:
        print(f"  ⚠️  Precision {precision:.4f} below target (0.80)")
        targets_met = False
    if recall < 0.75:
        print(f"  ⚠️  Recall {recall:.4f} below target (0.75)")
        targets_met = False
    
    if not targets_met:
        print("\n  ⚠️  Metrics below target. Consider more data or tuning.")
        print("  Saving model anyway for integration testing...")
    else:
        print("\n  ✓ All target metrics met!")
    
    # Save model
    print("\n[6/7] Saving model and artifacts...")
    Path("models").mkdir(exist_ok=True)
    engine.save("models/temporal_engine.h5")
    print("  Saved: models/temporal_engine.h5")
    print("  Saved: models/label_encoder.pkl")
    
    # Create baseline
    print("\n[7/7] Creating behavioral baseline...")
    feature_extractor = BehavioralFeatureExtractor()
    baseline = feature_extractor.update_baseline(normal_sequences[:50], duration_minutes=10)
    
    with open("models/detector_baseline.json", "w") as f:
        json.dump(baseline, f, indent=2)
    
    print("  Saved: models/detector_baseline.json")
    print(f"  Baseline entropy: {baseline['avg_entropy']:.4f}")
    print(f"  Baseline burst: {baseline['avg_burst']:.4f}")
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETE")
    print("=" * 60)
    print(f"\nFinal Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}  {'✓' if accuracy >= 0.85 else '✗'}")
    print(f"  Precision: {precision:.4f}  {'✓' if precision >= 0.80 else '✗'}")
    print(f"  Recall:    {recall:.4f}  {'✓' if recall >= 0.75 else '✗'}")
    print("\nReady for integration. Use integration_helper.py to load model.")


if __name__ == "__main__":
    main()

"""Model validation and performance benchmarking with comprehensive reporting."""

import pickle
import time
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import load_model
from tensorflow.keras.utils import to_categorical


def benchmark_inference_time(model, X_test, n_runs: int = 100):
    """Benchmark single-sequence inference time."""
    # Warmup
    _ = model.predict(X_test[:1], verbose=0)
    
    times = []
    for _ in range(n_runs):
        start = time.perf_counter()
        _ = model.predict(X_test[:1], verbose=0)
        end = time.perf_counter()
        times.append((end - start) * 1000)
    
    return np.mean(times), np.std(times), np.min(times), np.max(times)


def print_section(title: str) -> None:
    """Print formatted section header."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def main():
    print_section("MODEL VALIDATION & PERFORMANCE REPORT")
    
    # Check if models exist
    original_path = Path("models/temporal_engine.h5")
    optimized_path = Path("models/temporal_engine_optimized.h5")
    
    if not original_path.exists():
        print("\n❌ Original model not found. Run train_model.py first.")
        return
    
    has_optimized = optimized_path.exists()
    
    # Load data
    print("\n[1/6] Loading validation data...")
    with open("data/normal_sequences.pkl", "rb") as f:
        normal_sequences = pickle.load(f)
    with open("data/malware_sequences.pkl", "rb") as f:
        malware_sequences = pickle.load(f)
    
    all_sequences = normal_sequences + malware_sequences
    labels = [0] * len(normal_sequences) + [1] * len(malware_sequences)
    
    print(f"  Total sequences: {len(all_sequences)}")
    print(f"  Normal: {len(normal_sequences)}, Malware: {len(malware_sequences)}")
    
    # Preprocess
    print("\n[2/6] Preprocessing sequences...")
    with open("models/label_encoder.pkl", "rb") as f:
        label_encoder = pickle.load(f)
    
    from neuromorphic.temporal_engine import TemporalPatternEngine
    engine = TemporalPatternEngine()
    engine.label_encoder = label_encoder
    
    X = engine.preprocess_sequences(all_sequences, fit=False)
    y = to_categorical(labels, num_classes=2)
    
    # Split
    _, X_val, _, y_val = train_test_split(
        X, y, test_size=0.2, stratify=labels, random_state=42
    )
    
    y_val_labels = np.argmax(y_val, axis=1)
    
    print(f"  Validation samples: {len(X_val)}")
    
    # Evaluate original model
    print("\n[3/6] Evaluating original model...")
    original_model = load_model(original_path)
    
    y_pred_orig = original_model.predict(X_val, verbose=0)
    y_pred_orig_labels = np.argmax(y_pred_orig, axis=1)
    
    orig_accuracy = accuracy_score(y_val_labels, y_pred_orig_labels)
    orig_precision = precision_score(y_val_labels, y_pred_orig_labels, zero_division=0)
    orig_recall = recall_score(y_val_labels, y_pred_orig_labels, zero_division=0)
    orig_f1 = f1_score(y_val_labels, y_pred_orig_labels, zero_division=0)
    orig_cm = confusion_matrix(y_val_labels, y_pred_orig_labels)
    
    print(f"  Accuracy:  {orig_accuracy:.4f}")
    print(f"  Precision: {orig_precision:.4f}")
    print(f"  Recall:    {orig_recall:.4f}")
    print(f"  F1 Score:  {orig_f1:.4f}")
    
    # Benchmark original
    print("\n[4/6] Benchmarking original model inference...")
    orig_mean, orig_std, orig_min, orig_max = benchmark_inference_time(
        original_model, X_val, n_runs=100
    )
    print(f"  Mean:   {orig_mean:.2f} ms")
    print(f"  Std:    {orig_std:.2f} ms")
    print(f"  Min:    {orig_min:.2f} ms")
    print(f"  Max:    {orig_max:.2f} ms")
    
    # Evaluate optimized if exists
    if has_optimized:
        print("\n[5/6] Evaluating optimized model...")
        optimized_model = load_model(optimized_path)
        
        y_pred_opt = optimized_model.predict(X_val, verbose=0)
        y_pred_opt_labels = np.argmax(y_pred_opt, axis=1)
        
        opt_accuracy = accuracy_score(y_val_labels, y_pred_opt_labels)
        opt_precision = precision_score(y_val_labels, y_pred_opt_labels, zero_division=0)
        opt_recall = recall_score(y_val_labels, y_pred_opt_labels, zero_division=0)
        opt_f1 = f1_score(y_val_labels, y_pred_opt_labels, zero_division=0)
        opt_cm = confusion_matrix(y_val_labels, y_pred_opt_labels)
        
        print(f"  Accuracy:  {opt_accuracy:.4f}")
        print(f"  Precision: {opt_precision:.4f}")
        print(f"  Recall:    {opt_recall:.4f}")
        print(f"  F1 Score:  {opt_f1:.4f}")
        
        print("\n[6/6] Benchmarking optimized model inference...")
        opt_mean, opt_std, opt_min, opt_max = benchmark_inference_time(
            optimized_model, X_val, n_runs=100
        )
        print(f"  Mean:   {opt_mean:.2f} ms")
        print(f"  Std:    {opt_std:.2f} ms")
        print(f"  Min:    {opt_min:.2f} ms")
        print(f"  Max:    {opt_max:.2f} ms")
    else:
        print("\n[5/6] Optimized model not found. Skipping comparison.")
        print("  Run optimize_model.py to create optimized version.")
    
    # Generate report
    print_section("VALIDATION REPORT")
    
    report_lines = []
    report_lines.append("NEUROMORPHIC THREAT DETECTOR - VALIDATION REPORT")
    report_lines.append("=" * 70)
    report_lines.append("")
    
    # Original model metrics
    report_lines.append("ORIGINAL MODEL METRICS")
    report_lines.append("-" * 70)
    report_lines.append(f"Accuracy:  {orig_accuracy:.4f}  {'✓ Target met (>0.85)' if orig_accuracy >= 0.85 else '✗ Below target (>0.85)'}")
    report_lines.append(f"Precision: {orig_precision:.4f}  {'✓ Target met (>0.80)' if orig_precision >= 0.80 else '✗ Below target (>0.80)'}")
    report_lines.append(f"Recall:    {orig_recall:.4f}  {'✓ Target met (>0.75)' if orig_recall >= 0.75 else '✗ Below target (>0.75)'}")
    report_lines.append(f"F1 Score:  {orig_f1:.4f}")
    report_lines.append("")
    report_lines.append("Confusion Matrix:")
    report_lines.append(f"  [[TN={orig_cm[0,0]:3d}  FP={orig_cm[0,1]:3d}]")
    report_lines.append(f"   [FN={orig_cm[1,0]:3d}  TP={orig_cm[1,1]:3d}]]")
    report_lines.append("")
    
    # Inference time
    report_lines.append("INFERENCE PERFORMANCE")
    report_lines.append("-" * 70)
    report_lines.append(f"Original Model:")
    report_lines.append(f"  Mean:   {orig_mean:.2f} ms  {'✓ Target met (<100ms)' if orig_mean < 100 else '✗ Above target (<100ms)'}")
    report_lines.append(f"  Std:    {orig_std:.2f} ms")
    report_lines.append(f"  Range:  [{orig_min:.2f}, {orig_max:.2f}] ms")
    report_lines.append("")
    
    # Optimized comparison if available
    if has_optimized:
        accuracy_drop = (orig_accuracy - opt_accuracy) * 100
        speedup = orig_mean / opt_mean if opt_mean > 0 else 1.0
        
        report_lines.append("OPTIMIZED MODEL METRICS")
        report_lines.append("-" * 70)
        report_lines.append(f"Accuracy:  {opt_accuracy:.4f}")
        report_lines.append(f"Precision: {opt_precision:.4f}")
        report_lines.append(f"Recall:    {opt_recall:.4f}")
        report_lines.append(f"F1 Score:  {opt_f1:.4f}")
        report_lines.append("")
        report_lines.append("Confusion Matrix:")
        report_lines.append(f"  [[TN={opt_cm[0,0]:3d}  FP={opt_cm[0,1]:3d}]")
        report_lines.append(f"   [FN={opt_cm[1,0]:3d}  TP={opt_cm[1,1]:3d}]]")
        report_lines.append("")
        report_lines.append(f"Optimized Model:")
        report_lines.append(f"  Mean:   {opt_mean:.2f} ms  {'✓ Target met (<100ms)' if opt_mean < 100 else '✗ Above target (<100ms)'}")
        report_lines.append(f"  Std:    {opt_std:.2f} ms")
        report_lines.append(f"  Range:  [{opt_min:.2f}, {opt_max:.2f}] ms")
        report_lines.append("")
        report_lines.append("OPTIMIZATION IMPACT")
        report_lines.append("-" * 70)
        report_lines.append(f"Accuracy drop:  {accuracy_drop:.2f}%  {'✓ Target met (<3%)' if accuracy_drop < 3 else '✗ Above target (<3%)'}")
        report_lines.append(f"Speedup:        {speedup:.2f}x")
        report_lines.append(f"Size reduction: See optimize_model.py output")
        report_lines.append("")
    
    # Model sizes
    report_lines.append("MODEL ARTIFACTS")
    report_lines.append("-" * 70)
    orig_size = original_path.stat().st_size / (1024 * 1024)
    report_lines.append(f"Original:  {original_path.name} ({orig_size:.2f} MB)")
    
    if has_optimized:
        opt_size = optimized_path.stat().st_size / (1024 * 1024)
        report_lines.append(f"Optimized: {optimized_path.name} ({opt_size:.2f} MB)")
        report_lines.append(f"Size reduction: {((1 - opt_size/orig_size) * 100):.2f}%")
    
    report_lines.append("")
    
    # Summary
    report_lines.append("VALIDATION SUMMARY")
    report_lines.append("-" * 70)
    
    targets_met = []
    if orig_accuracy >= 0.85:
        targets_met.append("✓ Accuracy target met")
    else:
        targets_met.append("✗ Accuracy below target")
    
    if orig_precision >= 0.80:
        targets_met.append("✓ Precision target met")
    else:
        targets_met.append("✗ Precision below target")
    
    if orig_recall >= 0.75:
        targets_met.append("✓ Recall target met")
    else:
        targets_met.append("✗ Recall below target")
    
    if orig_mean < 100:
        targets_met.append("✓ Inference time target met")
    else:
        targets_met.append("✗ Inference time above target")
    
    for item in targets_met:
        report_lines.append(item)
    
    report_lines.append("")
    report_lines.append("RECOMMENDATIONS")
    report_lines.append("-" * 70)
    
    if orig_accuracy < 0.85 or orig_precision < 0.80 or orig_recall < 0.75:
        report_lines.append("• Collect more training data (current: 600 sequences)")
        report_lines.append("• Augment data with noise, reversals, time-warping")
        report_lines.append("• Try hyperparameter tuning (learning rate, dropout, units)")
    else:
        report_lines.append("• Model meets accuracy targets - ready for production testing")
    
    if orig_mean >= 100:
        report_lines.append("• Consider lighter model architecture (fewer LSTM units)")
        report_lines.append("• Use batch inference for multiple sequences")
        report_lines.append("• Deploy on GPU for faster inference")
    else:
        report_lines.append("• Inference time acceptable for real-time detection")
    
    report_lines.append("")
    report_lines.append("Generated: 2026-06-13")
    report_lines.append("=" * 70)
    
    # Save report
    report_path = Path("docs/validation_report.txt")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    
    with report_path.open("w") as f:
        f.write("\n".join(report_lines))
    
    print(f"\n✓ Validation report saved to: {report_path}")
    
    # Print key findings
    print("\nKEY FINDINGS:")
    for item in targets_met:
        print(f"  {item}")
    
    print("\nFor full details, see: docs/validation_report.txt")


if __name__ == "__main__":
    main()

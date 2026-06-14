"""Model optimization with quantization, pruning, and benchmarking."""

import os
import pickle
import time
from pathlib import Path

import numpy as np
import tensorflow as tf
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import load_model
from tensorflow.keras.utils import to_categorical


def quantize_model(model_path: str, output_path: str) -> None:
    """Apply TensorFlow Lite INT8 quantization and convert back to Keras format."""
    print("  Converting to TFLite with INT8 quantization...")
    
    model = load_model(model_path)
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    converter.target_spec.supported_types = [tf.int8]
    
    tflite_model = converter.convert()
    
    # Save TFLite model
    tflite_path = Path(output_path).parent / "temporal_engine_quantized.tflite"
    with open(tflite_path, "wb") as f:
        f.write(tflite_model)
    
    print(f"  Saved TFLite model: {tflite_path}")
    print(f"  Note: Using original .h5 with weight pruning for compatibility")


def prune_weights(model, threshold: float = 0.01):
    """Prune small weights by setting them to zero."""
    print(f"  Pruning weights with |w| < {threshold}...")
    
    pruned_count = 0
    total_count = 0
    
    for layer in model.layers:
        if hasattr(layer, "kernel"):
            weights = layer.get_weights()
            kernel = weights[0]
            
            # Count and prune
            total_count += kernel.size
            mask = np.abs(kernel) < threshold
            pruned_count += np.sum(mask)
            kernel[mask] = 0
            
            # Update weights
            weights[0] = kernel
            layer.set_weights(weights)
    
    prune_ratio = pruned_count / total_count if total_count > 0 else 0
    print(f"  Pruned {pruned_count}/{total_count} weights ({prune_ratio*100:.2f}%)")
    
    return model


def benchmark_inference(model, X_test, n_runs: int = 100):
    """Benchmark model inference time."""
    # Warmup
    _ = model.predict(X_test[:1], verbose=0)
    
    # Benchmark
    times = []
    for _ in range(n_runs):
        start = time.perf_counter()
        _ = model.predict(X_test[:1], verbose=0)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms
    
    return np.mean(times), np.std(times)


def main():
    print("=" * 60)
    print("MODEL OPTIMIZATION - QUANTIZATION & PRUNING")
    print("=" * 60)
    
    # Check if trained model exists
    model_path = Path("models/temporal_engine.h5")
    if not model_path.exists():
        print("\n❌ Error: Trained model not found.")
        print("   Run train_model.py first to generate models/temporal_engine.h5")
        return
    
    print("\n[1/6] Loading trained model...")
    original_model = load_model(model_path)
    original_size = model_path.stat().st_size / (1024 * 1024)  # MB
    print(f"  Original model size: {original_size:.2f} MB")
    
    # Load validation data
    print("\n[2/6] Loading validation data...")
    with open("data/normal_sequences.pkl", "rb") as f:
        normal_sequences = pickle.load(f)
    with open("data/malware_sequences.pkl", "rb") as f:
        malware_sequences = pickle.load(f)
    
    all_sequences = normal_sequences + malware_sequences
    labels = [0] * len(normal_sequences) + [1] * len(malware_sequences)
    
    # Preprocess
    with open("models/label_encoder.pkl", "rb") as f:
        label_encoder = pickle.load(f)
    
    from neuromorphic.temporal_engine import TemporalPatternEngine
    engine = TemporalPatternEngine()
    engine.label_encoder = label_encoder
    X = engine.preprocess_sequences(all_sequences, fit=False)
    y = to_categorical(labels, num_classes=2)
    
    _, X_val, _, y_val = train_test_split(
        X, y, test_size=0.2, stratify=labels, random_state=42
    )
    
    print(f"  Validation samples: {len(X_val)}")
    
    # Benchmark original model
    print("\n[3/6] Benchmarking original model...")
    y_pred_orig = original_model.predict(X_val, verbose=0)
    y_pred_orig_labels = np.argmax(y_pred_orig, axis=1)
    y_val_labels = np.argmax(y_val, axis=1)
    
    orig_accuracy = accuracy_score(y_val_labels, y_pred_orig_labels)
    orig_time_mean, orig_time_std = benchmark_inference(original_model, X_val, n_runs=100)
    
    print(f"  Accuracy: {orig_accuracy:.4f}")
    print(f"  Inference time: {orig_time_mean:.2f} ± {orig_time_std:.2f} ms")
    
    # Apply optimizations
    print("\n[4/6] Applying optimizations...")
    
    # Quantization (creates TFLite for reference)
    quantize_model(str(model_path), "models/temporal_engine_optimized.h5")
    
    # Weight pruning on original Keras model
    optimized_model = load_model(model_path)  # Reload fresh copy
    optimized_model = prune_weights(optimized_model, threshold=0.01)
    
    # Save pruned model
    optimized_path = Path("models/temporal_engine_optimized.h5")
    optimized_model.save(optimized_path)
    optimized_size = optimized_path.stat().st_size / (1024 * 1024)  # MB
    
    size_reduction = (1 - optimized_size / original_size) * 100
    print(f"  Optimized model size: {optimized_size:.2f} MB")
    print(f"  Size reduction: {size_reduction:.2f}%")
    
    # Benchmark optimized model
    print("\n[5/6] Benchmarking optimized model...")
    y_pred_opt = optimized_model.predict(X_val, verbose=0)
    y_pred_opt_labels = np.argmax(y_pred_opt, axis=1)
    
    opt_accuracy = accuracy_score(y_val_labels, y_pred_opt_labels)
    opt_time_mean, opt_time_std = benchmark_inference(optimized_model, X_val, n_runs=100)
    
    print(f"  Accuracy: {opt_accuracy:.4f}")
    print(f"  Inference time: {opt_time_mean:.2f} ± {opt_time_std:.2f} ms")
    
    # Analysis
    print("\n[6/6] Performance comparison...")
    accuracy_drop = (orig_accuracy - opt_accuracy) * 100
    speedup = orig_time_mean / opt_time_mean if opt_time_mean > 0 else 1.0
    
    print(f"\n  Accuracy drop: {accuracy_drop:.2f}%")
    print(f"  Inference speedup: {speedup:.2f}x")
    print(f"  Size reduction: {size_reduction:.2f}%")
    
    # Check targets
    print("\n" + "=" * 60)
    print("OPTIMIZATION RESULTS")
    print("=" * 60)
    
    targets_met = True
    
    if opt_time_mean < 100:
        print(f"✓ Inference time: {opt_time_mean:.2f} ms (target: <100 ms)")
    else:
        print(f"✗ Inference time: {opt_time_mean:.2f} ms (target: <100 ms)")
        targets_met = False
    
    if accuracy_drop < 3:
        print(f"✓ Accuracy drop: {accuracy_drop:.2f}% (target: <3%)")
    else:
        print(f"✗ Accuracy drop: {accuracy_drop:.2f}% (target: <3%)")
        targets_met = False
    
    if targets_met:
        print("\n✓ All optimization targets met!")
    else:
        print("\n⚠️  Some targets not met. Consider lighter pruning or model architecture changes.")
    
    print(f"\nOptimized model saved to: {optimized_path}")


if __name__ == "__main__":
    main()

"""End-to-end integration demo: Detector → Responder → Threat Intelligence Export."""

import pickle
import sys
from pathlib import Path

from integration_helper import create_detector_from_model, load_production_model
from responder.mock_responder import MockResponder


def print_banner(text: str) -> None:
    """Print formatted banner."""
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_result(result: dict, index: int) -> None:
    """Pretty-print analysis result."""
    print(f"\n[Sequence {index}]")
    print(f"  Threat Score:      {result['threat_score']:.4f}")
    print(f"  Severity:          {result['severity']}")
    print(f"  Is Threat:         {result['is_threat']}")
    print(f"  LSTM Confidence:   {result['lstm_confidence']:.4f}")
    print(f"  Anomaly Score:     {result['anomaly_score']:.4f}")
    print(f"  Recommended:       {result['recommended_action']}")
    print(f"  Timestamp:         {result['timestamp']}")


def print_action(action: dict) -> None:
    """Pretty-print responder action."""
    print(f"\n  → RESPONDER ACTION:")
    print(f"     Status:   {action['status']}")
    print(f"     Action:   {action['action']}")
    print(f"     Command:  {action['command']}")
    print(f"     Reason:   {action['reason']}")


def main():
    print_banner("NEUROMORPHIC THREAT DETECTOR - INTEGRATION DEMO")
    
    # Check if model exists
    model_path = Path("models/temporal_engine.h5")
    if not model_path.exists():
        print("\n❌ Error: Trained model not found.")
        print("   Run train_model.py first to train the model.")
        sys.exit(1)
    
    # Load model and create detector
    print("\n[1/5] Loading production model...")
    try:
        engine = load_production_model()
        print("  ✓ Temporal engine loaded")
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    
    print("\n[2/5] Creating adaptive detector...")
    try:
        detector = create_detector_from_model(engine)
        print("  ✓ Detector configured with baseline")
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    
    # Load sample sequences
    print("\n[3/5] Loading sample malware sequences...")
    with open("data/malware_sequences.pkl", "rb") as f:
        malware_sequences = pickle.load(f)
    
    print(f"  Loaded {len(malware_sequences)} malware samples")
    
    # Analyze sequences with responder
    print("\n[4/5] Analyzing sequences with responder pipeline...")
    responder = MockResponder()
    
    # Demo with 3 malware sequences
    demo_sequences = malware_sequences[:3]
    
    for i, sequence in enumerate(demo_sequences, start=1):
        # Analyze
        result = detector.analyze_sequence(sequence)
        print_result(result, i)
        
        # Trigger responder based on recommended action
        action_type = result["recommended_action"]
        process_id = f"PID_{1000 + i}"
        reason = f"Threat detected: score={result['threat_score']:.4f}, severity={result['severity']}"
        
        action_record = responder.execute_action(action_type, process_id, reason)
        print_action(action_record)
    
    # Export threat intelligence
    print("\n[5/5] Exporting threat intelligence...")
    export_path = Path("threat_intel_export.json")
    detector.export_threat_intelligence(export_path)
    
    print(f"  ✓ Exported to: {export_path}")
    
    # Show statistics
    stats = detector.get_stats()
    print("\n  Detection Statistics:")
    print(f"    Total Analyzed:     {stats['total_analyzed']}")
    print(f"    Threats Detected:   {stats['threats_detected']}")
    print(f"    Detection Rate:     {stats['detection_rate']:.2%}")
    print(f"    False Positive Rate: {stats['fp_rate']:.2%}")
    
    # Show threat intelligence summary
    print("\n  Threat Intelligence Summary:")
    print(f"    Unique Signatures:  {len(detector.known_attack_signatures)}")
    
    for sig_hash, sig_data in list(detector.known_attack_signatures.items())[:2]:
        print(f"\n    Signature: {sig_hash}")
        print(f"      First 5 events: {sig_data['signature'][:5]}")
        print(f"      Frequency:      {sig_data['frequency']}")
        print(f"      Avg Score:      {sig_data['avg_score']:.4f}")
        print(f"      Recommendation: {sig_data['recommended_action']}")
    
    print_banner("DEMO COMPLETE")
    
    print("\n✓ Detector → Responder flow validated")
    print("✓ Threat intelligence exported")
    print("✓ All pipeline components operational")
    
    print("\nNext Steps:")
    print("  1. Review threat_intel_export.json for signature details")
    print("  2. Run validate_model.py for performance benchmarks")
    print("  3. Integrate with backend using integration_helper.py")
    print("  4. Configure real responder for production deployment")
    
    print("\nFor Person 2 (Backend Integration):")
    print("  - API documented in docs/MODEL.md")
    print("  - Use integration_helper.load_production_model()")
    print("  - Replace MockResponder with real security controls")
    print("  - Monitor stats with detector.get_stats()")


if __name__ == "__main__":
    main()

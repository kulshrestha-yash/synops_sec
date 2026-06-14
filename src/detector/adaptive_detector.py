"""Adaptive threat detector with ensemble scoring and threat intelligence tracking."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any


class AdaptiveThreatDetector:
    """Ensemble threat detector with adaptive thresholding and threat intelligence.
    
    Combines LSTM temporal predictions (50%), behavioral features (30%), and
    anomaly detection (20%) into a single threat score. Adapts detection
    threshold based on recent prediction distribution and maintains threat
    intelligence with rich metadata for security analysis.
    """

    def __init__(
        self,
        temporal_engine,
        feature_extractor,
        confidence_threshold: float = 0.6,
        adaptation_rate: float = 0.01,
    ) -> None:
        self.temporal_engine = temporal_engine
        self.feature_extractor = feature_extractor
        self.mock_engine = temporal_engine
        self.mock_extractor = feature_extractor
        self.confidence_threshold = confidence_threshold
        self.adaptation_rate = adaptation_rate
        
        self.recent_predictions: deque = deque(maxlen=1000)
        self.recent_results: deque = deque(maxlen=1000)
        self.false_positive_buffer: deque = deque(maxlen=100)
        self.attack_pattern_memory: deque = deque(maxlen=500)
        self.known_attack_signatures: dict[str, dict[str, Any]] = {}
        self.detection_stats = Counter()

    def analyze_sequence(
        self,
        event_sequence: list[str],
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze syscall sequence and return threat assessment with recommended action."""
        
        behavioral_features = self.feature_extractor.extract_temporal_features(event_sequence)
        lstm_result = self.temporal_engine.predict_threat(event_sequence)
        anomaly_score = self.feature_extractor.calculate_anomaly_score(event_sequence)
        
        lstm_confidence = lstm_result["threat_probability"]
        behavior_score = self._aggregate_behavioral_score(behavioral_features)
        
        ensemble_score = (
            lstm_confidence * 0.5 +
            behavior_score * 0.3 +
            anomaly_score * 0.2
        )
        
        if context:
            ensemble_score = self._apply_context_multipliers(ensemble_score, context)
        
        ensemble_score = min(ensemble_score, 1.0)
        is_threat = ensemble_score >= self.confidence_threshold
        severity, recommended_action = self._determine_action(ensemble_score)
        
        result = {
            "timestamp": datetime.now().isoformat(),
            "threat_score": ensemble_score,
            "is_threat": is_threat,
            "lstm_confidence": lstm_confidence,
            "anomaly_score": anomaly_score,
            "behavioral_features": behavioral_features,
            "recommended_action": recommended_action,
            "severity": severity,
            "sequence": list(event_sequence),
        }
        
        self.recent_predictions.append(ensemble_score)
        self.recent_results.append(result)
        self.detection_stats["total_analyzed"] += 1
        
        should_track_signature = is_threat or severity != "LOW"

        if is_threat:
            self.detection_stats["threats_detected"] += 1

        if should_track_signature:
            self._update_threat_intelligence(event_sequence, ensemble_score, result)
            self.attack_pattern_memory.append(event_sequence[:10])
        
        if len(self.recent_predictions) >= 100 and self.detection_stats["total_analyzed"] % 100 == 0:
            self._adapt_if_needed()
        
        return result

    def _aggregate_behavioral_score(self, features: dict[str, float]) -> float:
        """Aggregate behavioral features into single normalized score."""
        weights = {
            "shannon_entropy": 0.2,
            "burst_score": 0.25,
            "rare_event_ratio": 0.3,
            "repetition_score": 0.15,
            "event_density": 0.1,
        }
        
        normalized = {
            "shannon_entropy": min(features["shannon_entropy"] / 5.0, 1.0),
            "burst_score": min(features["burst_score"] / 5.0, 1.0),
            "rare_event_ratio": features["rare_event_ratio"],
            "repetition_score": features["repetition_score"],
            "event_density": min(features["event_density"], 1.0),
        }
        
        return sum(normalized[k] * weights[k] for k in weights)

    def _apply_context_multipliers(self, score: float, context: dict[str, Any]) -> float:
        """Apply context-based risk adjustments."""
        if context.get("privileged_process"):
            score *= 1.2
        if context.get("external_connection"):
            score *= 1.15
        if context.get("known_good"):
            score *= 0.5
        return score

    def _determine_action(self, score: float) -> tuple[str, dict[str, Any]]:
        """Map threat score to severity level and recommended action."""
        if score >= 0.85:
            return "CRITICAL", {
                "action": "IMMEDIATE_ISOLATION",
                "priority": "CRITICAL",
                "description": "Isolate process, block IPs, collect forensics, alert SIEM"
            }
        elif score >= 0.72:
            return "HIGH", {
                "action": "SUSPEND_AND_ANALYZE",
                "priority": "HIGH",
                "description": "Suspend process and analyze behavior with intensive logging"
            }
        elif score >= 0.6:
            return "MEDIUM", {
                "action": "ENHANCED_MONITORING",
                "priority": "MEDIUM",
                "description": "Enable enhanced monitoring and threshold watch"
            }
        else:
            return "LOW", {
                "action": "CONTINUE_MONITORING",
                "priority": "LOW",
                "description": "Continue baseline monitoring"
            }

    def _update_threat_intelligence(
        self,
        sequence: list[str],
        score: float,
        result: dict[str, Any],
    ) -> None:
        """Track attack signatures with rich metadata."""
        signature = tuple(sequence[:10])
        sig_hash = hashlib.sha256(str(signature).encode()).hexdigest()[:16]
        
        if sig_hash in self.known_attack_signatures:
            sig_data = self.known_attack_signatures[sig_hash]
            sig_data["frequency"] += 1
            sig_data["avg_score"] = (sig_data["avg_score"] * (sig_data["frequency"] - 1) + score) / sig_data["frequency"]
            sig_data["last_seen"] = datetime.now().isoformat()
            sig_data["confidence_trend"].append(score)
            
            seq_hash = hashlib.sha256(str(sequence).encode()).hexdigest()[:16]
            if seq_hash not in sig_data["related_sequences"]:
                sig_data["related_sequences"].append(seq_hash)
        else:
            self.known_attack_signatures[sig_hash] = {
                "signature": list(signature),
                "frequency": 1,
                "avg_score": score,
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "related_sequences": [hashlib.sha256(str(sequence).encode()).hexdigest()[:16]],
                "confidence_trend": deque([score], maxlen=10),
                "recommended_action": result["recommended_action"],
            }

    def _adapt_if_needed(self) -> None:
        """Adjust detection threshold based on recent prediction drift."""
        if len(self.recent_predictions) < 100:
            return
        
        recent_mean = mean(list(self.recent_predictions)[-100:])
        historical_mean = mean(self.recent_predictions)
        
        drift_detected = abs(recent_mean - historical_mean) > 0.2
        sustained_high_risk = recent_mean >= self.confidence_threshold + 0.08
        sustained_low_risk = recent_mean <= max(self.confidence_threshold - 0.35, 0.2)

        if drift_detected or sustained_high_risk or sustained_low_risk:
            previous_threshold = self.confidence_threshold
            adjustment = self.adaptation_rate * (0.5 - recent_mean)
            self.confidence_threshold += adjustment
            self.confidence_threshold = max(0.5, min(0.9, self.confidence_threshold))
            if self.confidence_threshold != previous_threshold:
                self.detection_stats["adaptations_made"] += 1

    def report_false_positive(self, sequence: list[str]) -> None:
        """Register false positive and adjust threshold if needed."""
        self.false_positive_buffer.append(sequence)
        self.detection_stats["false_positives"] += 1
        
        if len(self.false_positive_buffer) > 20:
            self.confidence_threshold += 0.05
            self.confidence_threshold = min(0.9, self.confidence_threshold)

    def get_stats(self) -> dict[str, float]:
        """Return detection performance statistics."""
        total = self.detection_stats["total_analyzed"]
        threats = self.detection_stats["threats_detected"]
        fps = self.detection_stats["false_positives"]
        
        return {
            "total_analyzed": total,
            "threats_detected": threats,
            "false_positives": fps,
            "detection_rate": threats / total if total > 0 else 0.0,
            "fp_rate": fps / total if total > 0 else 0.0,
        }

    def export_threat_intelligence(self, filepath: str | Path) -> None:
        """Export threat signatures with rich metadata to JSON."""
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        export_data = {}
        for sig_hash, sig_data in self.known_attack_signatures.items():
            export_data[sig_hash] = {
                "signature": sig_data["signature"],
                "frequency": sig_data["frequency"],
                "avg_score": sig_data["avg_score"],
                "first_seen": sig_data["first_seen"],
                "last_seen": sig_data["last_seen"],
                "related_sequences": sig_data["related_sequences"],
                "confidence_trend": list(sig_data["confidence_trend"]),
                "recommended_action": sig_data["recommended_action"],
            }
        
        with filepath.open("w") as f:
            json.dump(export_data, f, indent=2)

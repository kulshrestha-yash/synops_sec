"""Behavioral feature extraction for malware-oriented sequence analysis."""

from __future__ import annotations

import math
from collections import Counter, deque
from statistics import mean, pstdev
from typing import Any, Iterable, Sequence


class BehavioralFeatureExtractor:
    """Extract temporal and network behavior signals from event streams.

    The extractor keeps a bounded sliding window so callers can repeatedly feed
    recent process or network events without retaining an unbounded history.
    Features are designed to highlight common malware behaviors such as bursty
    execution, repeated action loops, rare suspicious API/syscall usage, and
    regular command-and-control beaconing.
    """

    SUSPICIOUS_EVENTS = {
        "encrypt",
        "inject",
        "hook",
        "pack",
        "obfuscate",
        "unlink",
        "connect",
        "execve",
        "exfil",
        "mmap",
        "mprotect",
    }
    SUSPICIOUS_PORTS = {4444, 5555, 6666, 31337}

    def __init__(self, window_size: int = 100) -> None:
        """Initialize the sliding event window.

        Args:
            window_size: Maximum number of recent events retained in the buffer.
        """

        if window_size <= 0:
            raise ValueError("window_size must be greater than zero.")

        self.window_size = window_size
        self.event_buffer: deque[str] = deque(maxlen=window_size)
        self.baseline: dict[str, float] | None = None

    def extract_temporal_features(self, event_sequence: Sequence[Any]) -> dict[str, float]:
        """Calculate temporal behavior features from an event sequence."""

        events = [self._event_name(event) for event in event_sequence]
        self.event_buffer.extend(events)

        entropy = self._shannon_entropy(events)
        window_counts = self._activity_window_counts(events)
        total_events = len(events)
        event_counts = Counter(events)
        rare_event_hits = sum(
            count
            for event, count in event_counts.items()
            if event in self.SUSPICIOUS_EVENTS
        )

        # High entropy can indicate polymorphic or obfuscated behavior because
        # the event distribution is less predictable than ordinary workflows.
        shannon_entropy = entropy

        # Malware often performs short intense runs, such as file encryption or
        # injection loops, so activity count variance across windows is useful.
        burst_score = pstdev(window_counts) if len(window_counts) > 1 else 0.0

        # Calls like encrypt/inject/hook/pack/obfuscate are uncommon in benign
        # syscall traces and tend to appear in malware tooling or payload setup.
        rare_event_ratio = rare_event_hits / total_events if total_events else 0.0

        # Repeated 3-grams expose tight behavioral loops, such as repeatedly
        # reading, transforming, and writing files during ransomware activity.
        repetition_score = self._repetition_score(events)

        # Dense event streams can signal automation doing many actions in a
        # short behavioral window instead of slower human-driven interaction.
        event_density = total_events / self.window_size

        return {
            "shannon_entropy": shannon_entropy,
            "burst_score": burst_score,
            "rare_event_ratio": rare_event_ratio,
            "repetition_score": repetition_score,
            "event_density": event_density,
        }

    def extract_network_features(self, packet_sequence: Sequence[Any]) -> dict[str, float]:
        """Calculate network behavior features from packet or connection data."""

        ports: list[int] = []
        payload_sizes: list[float] = []
        timestamps: list[float] = []

        for packet in packet_sequence:
            port = self._packet_value(
                packet,
                ("destination_port", "dest_port", "dst_port", "dport", "port"),
                tuple_index=0,
            )
            payload_size = self._packet_value(
                packet,
                ("payload_size", "payload_len", "length", "size", "bytes"),
                tuple_index=1,
            )
            timestamp = self._packet_value(
                packet,
                ("timestamp", "time", "ts"),
                tuple_index=2,
            )

            if port is not None:
                ports.append(int(port))
            if payload_size is not None:
                payload_sizes.append(float(payload_size))
            if timestamp is not None:
                timestamps.append(float(timestamp))

        suspicious_hits = sum(1 for port in ports if port in self.SUSPICIOUS_PORTS)
        intervals = [
            later - earlier
            for earlier, later in zip(sorted(timestamps), sorted(timestamps)[1:])
            if later >= earlier
        ]
        interval_std = pstdev(intervals) if len(intervals) > 1 else 0.0

        # Many malware families reuse ports associated with shells, backdoors,
        # and commodity tooling; hits are therefore a compact risk signal.
        suspicious_port_hits = float(suspicious_hits)

        # Payload size variance helps separate steady benign traffic from staged
        # exfiltration, command responses, or packed binary transfer behavior.
        avg_payload_size = mean(payload_sizes) if payload_sizes else 0.0
        payload_size_variance = self._variance(payload_sizes)

        # Beaconing is suspicious when connections occur with machine-like
        # regularity, so lower interval variance produces a higher score.
        beaconing_score = 1.0 / interval_std if interval_std > 0 else 0.0

        return {
            "unique_destination_ports": float(len(set(ports))),
            "suspicious_port_hits": suspicious_port_hits,
            "avg_payload_size": avg_payload_size,
            "payload_size_variance": payload_size_variance,
            "beaconing_score": beaconing_score,
        }

    def update_baseline(
        self,
        normal_events: Sequence[Any] | Sequence[Sequence[Any]],
        duration_minutes: float = 10,
    ) -> dict[str, float]:
        """Learn normal temporal behavior statistics from benign training data."""

        if duration_minutes <= 0:
            raise ValueError("duration_minutes must be greater than zero.")

        sequences = self._normalize_event_batches(normal_events)
        if not sequences:
            raise ValueError("normal_events must contain at least one event.")

        per_sequence_features = [
            self.extract_temporal_features(sequence) for sequence in sequences
        ]
        flattened_events = [
            self._event_name(event)
            for sequence in sequences
            for event in sequence
        ]
        total_events = len(flattened_events)

        entropy_values = [
            features["shannon_entropy"] for features in per_sequence_features
        ]
        burst_values = [features["burst_score"] for features in per_sequence_features]
        density_values = [
            features["event_density"] for features in per_sequence_features
        ]

        event_rate = total_events / duration_minutes
        self.baseline = {
            "avg_entropy": mean(entropy_values),
            "std_entropy": pstdev(entropy_values) if len(entropy_values) > 1 else 0.0,
            "avg_burst": mean(burst_values),
            "std_burst": pstdev(burst_values) if len(burst_values) > 1 else 0.0,
            "avg_event_rate": event_rate,
            "avg_event_density": mean(density_values),
            "std_event_density": pstdev(density_values)
            if len(density_values) > 1
            else 0.0,
        }
        return self.baseline

    def calculate_anomaly_score(self, event_sequence: Sequence[Any]) -> float:
        """Compare sequence behavior against the learned baseline.

        Returns:
            A normalized deviation score in the range ``0.0`` to ``1.0``.
        """

        if self.baseline is None:
            raise ValueError("Baseline is not set. Call update_baseline first.")

        features = self.extract_temporal_features(event_sequence)

        deviations = [
            self._normalized_deviation(
                features["shannon_entropy"],
                self.baseline["avg_entropy"],
                self.baseline["std_entropy"],
            ),
            self._normalized_deviation(
                features["burst_score"],
                self.baseline["avg_burst"],
                self.baseline["std_burst"],
            ),
            self._normalized_deviation(
                features["event_density"],
                self.baseline["avg_event_density"],
                self.baseline["std_event_density"],
            ),
            features["rare_event_ratio"] * 12.0,
        ]

        raw_score = mean(deviations)
        return raw_score / (1.0 + raw_score)

    def _shannon_entropy(self, events: Sequence[str]) -> float:
        total = len(events)
        if total == 0:
            return 0.0

        counts = Counter(events)
        return -sum(
            (count / total) * math.log2(count / total)
            for count in counts.values()
        )

    def _activity_window_counts(self, events: Sequence[str]) -> list[int]:
        if not events:
            return [0]

        return [
            len(events[index : index + self.window_size])
            for index in range(0, len(events), self.window_size)
        ]

    def _repetition_score(self, events: Sequence[str]) -> float:
        trigrams = [
            tuple(events[index : index + 3])
            for index in range(0, max(len(events) - 2, 0))
        ]
        if not trigrams:
            return 0.0

        return 1.0 - (len(set(trigrams)) / len(trigrams))

    def _normalize_event_batches(
        self,
        events: Sequence[Any] | Sequence[Sequence[Any]],
    ) -> list[list[Any]]:
        if len(events) == 0:
            return []

        first_event = events[0]
        if isinstance(first_event, (str, bytes)) or not isinstance(
            first_event, Sequence
        ):
            return [list(events)]

        return [list(sequence) for sequence in events]  # type: ignore[arg-type]

    def _event_name(self, event: Any) -> str:
        if isinstance(event, str):
            return event
        if isinstance(event, dict):
            return str(event.get("event") or event.get("name") or event.get("call"))
        return str(getattr(event, "event", getattr(event, "name", event)))

    def _packet_value(
        self,
        packet: Any,
        keys: Iterable[str],
        tuple_index: int,
    ) -> Any | None:
        if isinstance(packet, dict):
            for key in keys:
                if key in packet:
                    return packet[key]
            return None

        if isinstance(packet, Sequence) and not isinstance(packet, (str, bytes)):
            return packet[tuple_index] if len(packet) > tuple_index else None

        for key in keys:
            if hasattr(packet, key):
                return getattr(packet, key)

        return None

    def _variance(self, values: Sequence[float]) -> float:
        if not values:
            return 0.0

        avg = mean(values)
        return mean([(value - avg) ** 2 for value in values])

    def _normalized_deviation(
        self,
        value: float,
        baseline_mean: float,
        baseline_std: float,
    ) -> float:
        scale = baseline_std if baseline_std > 0 else max(abs(baseline_mean), 1.0)
        return abs(value - baseline_mean) / scale

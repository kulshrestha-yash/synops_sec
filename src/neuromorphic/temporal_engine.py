"""Temporal pattern recognition engine for syscall threat detection.

This module implements a neuromorphic-inspired sequence classifier. The
recurrent gates in LSTM cells act like a small, trainable memory system: they
decide what to retain, update, and forget in a way that loosely echoes
biological memory consolidation. Bidirectional recurrent layers process the
same syscall stream forward and backward, resembling parallel neural pathways
that interpret temporal signals from complementary directions before a final
classification decision is made.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.layers import (
    LSTM,
    Bidirectional,
    Dense,
    Dropout,
    Embedding,
    Input,
)
from tensorflow.keras.metrics import Precision, Recall
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.preprocessing.sequence import pad_sequences


class TemporalPatternEngine:
    """Neuromorphic-inspired temporal classifier for system-call sequences.

    The model uses stacked LSTM layers to learn temporal motifs in syscall
    traces. LSTM gates mimic a biological memory process by learning when to
    preserve, suppress, or update signals across time, while bidirectional
    processing provides parallel forward and backward pathways over each trace.
    Together these mechanisms help the network recognize threat patterns whose
    meaning depends on both earlier and later events in the sequence.
    """

    def __init__(
        self,
        input_dim: int = 100,
        embedding_dim: int = 64,
        sequence_length: int = 50,
        models_dir: str | Path = "models",
    ) -> None:
        self.input_dim = input_dim
        self.embedding_dim = embedding_dim
        self.sequence_length = sequence_length
        self.models_dir = Path(models_dir)
        self.encoder_path = self.models_dir / "label_encoder.pkl"
        self.model = None
        self.label_encoder = LabelEncoder()

    def build_model(self, n_classes: int = 2) -> Sequential:
        """Build and compile the temporal neural architecture.

        Args:
            n_classes: Number of output classes. Binary threat detection uses
                two softmax units by default.

        Returns:
            A compiled Keras ``Sequential`` model using Adam, categorical
            crossentropy, and accuracy/precision/recall metrics.
        """

        model = Sequential(
            [
                Input(shape=(self.sequence_length,)),
                Embedding(
                    input_dim=self.input_dim,
                    output_dim=self.embedding_dim,
                ),
                Bidirectional(LSTM(128, return_sequences=True)),
                Dropout(0.3),
                Bidirectional(LSTM(64, return_sequences=True)),
                Dropout(0.3),
                LSTM(32, return_sequences=False),
                Dropout(0.3),
                Dense(64, activation="relu"),
                Dropout(0.2),
                Dense(32, activation="relu"),
                Dense(n_classes, activation="softmax"),
            ]
        )

        model.compile(
            optimizer=Adam(),
            loss="categorical_crossentropy",
            metrics=["accuracy", Precision(name="precision"), Recall(name="recall")],
        )
        self.model = model
        return model

    def preprocess_sequences(
        self,
        sequences: Sequence[str] | Sequence[Sequence[str]],
        fit: bool = False,
    ) -> np.ndarray:
        """Encode syscall text sequences and pad/truncate them to length 50.

        Args:
            sequences: A single syscall sequence or a batch of syscall
                sequences, where each syscall is represented as text.
            fit: When ``True``, fit the ``LabelEncoder`` on the provided
                syscalls and persist it to ``models/label_encoder.pkl``. When
                ``False``, use the current encoder or load the persisted one.

        Returns:
            A NumPy array of integer-encoded sequences with shape
            ``(n_sequences, 50)``.
        """

        normalized = self._normalize_sequences(sequences)
        flat_tokens = [token for sequence in normalized for token in sequence]

        if fit:
            if not flat_tokens:
                raise ValueError("Cannot fit LabelEncoder on empty sequences.")
            self.label_encoder.fit(flat_tokens)
            self._save_encoder()
        elif not self._encoder_is_fitted():
            self._load_encoder()

        encoded_sequences = [
            self._encode_sequence(sequence) for sequence in normalized
        ]

        return pad_sequences(
            encoded_sequences,
            maxlen=self.sequence_length,
            dtype="int32",
            padding="post",
            truncating="post",
            value=0,
        )

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        epochs: int = 50,
        batch_size: int = 32,
    ) -> Any:
        """Train the model with early stopping and best-checkpoint persistence.

        Args:
            X_train: Encoded training sequences.
            y_train: One-hot encoded training labels.
            X_val: Encoded validation sequences.
            y_val: One-hot encoded validation labels.
            epochs: Maximum number of training epochs.
            batch_size: Number of samples per gradient update.

        Returns:
            The Keras ``History`` object returned by ``model.fit``.
        """

        if self.model is None:
            n_classes = int(y_train.shape[-1]) if len(y_train.shape) > 1 else 2
            self.build_model(n_classes=n_classes)

        self.models_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_path = self.models_dir / "temporal_engine_best.h5"
        callbacks = [
            EarlyStopping(
                monitor="val_loss",
                patience=5,
                restore_best_weights=True,
            ),
            ModelCheckpoint(
                filepath=str(checkpoint_path),
                monitor="val_loss",
                save_best_only=True,
            ),
        ]

        return self.model.fit(
            X_train,
            y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
        )

    def predict_threat(self, sequence: Sequence[str]) -> dict[str, float | bool]:
        """Predict whether a syscall sequence is threatening.

        Args:
            sequence: A single syscall sequence represented as text tokens.

        Returns:
            A dictionary containing ``threat_probability``, ``is_threat``, and
            ``confidence``. Class index ``1`` is treated as the threat class.
        """

        if self.model is None:
            raise ValueError("Model is not built or loaded.")

        encoded = self.preprocess_sequences(sequence, fit=False)
        probabilities = self.model.predict(encoded, verbose=0)[0]
        threat_probability = float(probabilities[1])
        confidence = float(np.max(probabilities))

        return {
            "threat_probability": threat_probability,
            "is_threat": threat_probability >= 0.5,
            "confidence": confidence,
        }

    def save(self, path: str | Path) -> None:
        """Persist the trained Keras model to disk."""

        if self.model is None:
            raise ValueError("No model is available to save.")

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save(path)
        if self._encoder_is_fitted():
            self._save_encoder()

    def load(self, path: str | Path) -> Sequential:
        """Load a persisted Keras model and, when available, its encoder."""

        self.model = load_model(path)
        if self.encoder_path.exists():
            self._load_encoder()
        return self.model

    def _normalize_sequences(
        self,
        sequences: Sequence[str] | Sequence[Sequence[str]],
    ) -> list[list[str]]:
        if len(sequences) == 0:
            return []

        first_item = sequences[0]
        if isinstance(first_item, str):
            return [list(sequences)]  # type: ignore[list-item]

        return [list(sequence) for sequence in sequences]  # type: ignore[arg-type]

    def _encode_sequence(self, sequence: Iterable[str]) -> list[int]:
        known_tokens = set(self.label_encoder.classes_)
        encoded = []
        for token in sequence:
            if token in known_tokens:
                encoded.append(int(self.label_encoder.transform([token])[0]) + 1)
            else:
                encoded.append(0)

        max_token_id = self.input_dim - 1
        return [token_id if token_id <= max_token_id else 0 for token_id in encoded]

    def _encoder_is_fitted(self) -> bool:
        return hasattr(self.label_encoder, "classes_")

    def _save_encoder(self) -> None:
        self.models_dir.mkdir(parents=True, exist_ok=True)
        with self.encoder_path.open("wb") as file:
            pickle.dump(self.label_encoder, file)

    def _load_encoder(self) -> None:
        if not self.encoder_path.exists():
            raise FileNotFoundError(
                f"Label encoder not found at {self.encoder_path}. "
                "Call preprocess_sequences(..., fit=True) first."
            )

        with self.encoder_path.open("rb") as file:
            self.label_encoder = pickle.load(file)

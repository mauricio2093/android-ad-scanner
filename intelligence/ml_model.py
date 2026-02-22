from __future__ import annotations

import datetime
import json
import math
from dataclasses import dataclass

from .models import FeatureVector

ML_FEATURE_NAMES = [
    "permissions_total",
    "suspicious_permissions_count",
    "dangerous_permissions_count",
    "ad_sdk_hits",
    "tracker_hits",
    "suspicious_keyword_hits",
    "boot_receiver_detected",
    "accessibility_binding_detected",
    "overlay_permission_detected",
    "install_packages_permission_detected",
    "write_settings_detected",
    "apk_hash_present",
    "apk_size_kb",
]


@dataclass(slots=True)
class TrainingMetrics:
    samples: int
    accuracy: float
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict:
        return {
            "samples": self.samples,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


class SupervisedRiskModel:
    """Lightweight logistic model with gradient descent, no external ML deps."""

    model_name = "supervised_risk_v1"

    def __init__(
        self,
        *,
        means: dict[str, float] | None = None,
        stds: dict[str, float] | None = None,
        weights: dict[str, float] | None = None,
        bias: float = 0.0,
        version: str | None = None,
    ) -> None:
        self.means = means or {name: 0.0 for name in ML_FEATURE_NAMES}
        self.stds = stds or {name: 1.0 for name in ML_FEATURE_NAMES}
        self.weights = weights or {name: 0.0 for name in ML_FEATURE_NAMES}
        self.bias = bias
        self.version = version or datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    def fit(
        self,
        rows: list[tuple[FeatureVector, int]],
        *,
        epochs: int = 350,
        learning_rate: float = 0.08,
        l2: float = 0.001,
    ) -> TrainingMetrics:
        if len(rows) < 8:
            raise ValueError("Se requieren al menos 8 muestras etiquetadas para entrenar.")

        self._compute_scaler(rows)

        for _ in range(epochs):
            grad_w = {name: 0.0 for name in ML_FEATURE_NAMES}
            grad_b = 0.0
            n = float(len(rows))

            for features, label in rows:
                x = self._vectorize(features)
                logit = self.bias + sum(self.weights[name] * x[name] for name in ML_FEATURE_NAMES)
                pred = self._sigmoid(logit)
                err = pred - float(label)

                for name in ML_FEATURE_NAMES:
                    grad_w[name] += err * x[name]
                grad_b += err

            for name in ML_FEATURE_NAMES:
                grad = (grad_w[name] / n) + (l2 * self.weights[name])
                self.weights[name] -= learning_rate * grad

            self.bias -= learning_rate * (grad_b / n)

        return self.evaluate(rows)

    def evaluate(self, rows: list[tuple[FeatureVector, int]]) -> TrainingMetrics:
        tp = fp = tn = fn = 0

        for features, label in rows:
            score = self.predict_proba(features)
            pred = 1 if score >= 0.5 else 0
            if pred == 1 and label == 1:
                tp += 1
            elif pred == 1 and label == 0:
                fp += 1
            elif pred == 0 and label == 0:
                tn += 1
            else:
                fn += 1

        total = max(1, tp + fp + tn + fn)
        accuracy = (tp + tn) / total
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        if (precision + recall) == 0:
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)

        return TrainingMetrics(
            samples=total,
            accuracy=round(accuracy, 4),
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
        )

    def predict_proba(self, features: FeatureVector) -> float:
        x = self._vectorize(features)
        logit = self.bias + sum(self.weights[name] * x[name] for name in ML_FEATURE_NAMES)
        return round(self._sigmoid(logit), 6)

    def to_dict(self) -> dict:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "means": self.means,
            "stds": self.stds,
            "weights": self.weights,
            "bias": self.bias,
            "feature_names": list(ML_FEATURE_NAMES),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "SupervisedRiskModel":
        return cls(
            means={str(k): float(v) for k, v in dict(payload.get("means", {})).items()},
            stds={str(k): float(v) for k, v in dict(payload.get("stds", {})).items()},
            weights={str(k): float(v) for k, v in dict(payload.get("weights", {})).items()},
            bias=float(payload.get("bias", 0.0)),
            version=str(payload.get("version", "unknown")),
        )

    @classmethod
    def from_json(cls, payload_json: str) -> "SupervisedRiskModel":
        return cls.from_dict(json.loads(payload_json))

    def _compute_scaler(self, rows: list[tuple[FeatureVector, int]]) -> None:
        n = float(len(rows))
        means: dict[str, float] = {}
        stds: dict[str, float] = {}

        for name in ML_FEATURE_NAMES:
            values = [self._raw_value(features, name) for features, _ in rows]
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / max(1.0, n - 1.0)
            std = max(1e-6, math.sqrt(variance))
            means[name] = mean
            stds[name] = std

        self.means = means
        self.stds = stds

    def _vectorize(self, features: FeatureVector) -> dict[str, float]:
        vector: dict[str, float] = {}
        for name in ML_FEATURE_NAMES:
            value = self._raw_value(features, name)
            mean = self.means.get(name, 0.0)
            std = self.stds.get(name, 1.0)
            vector[name] = (value - mean) / std
        return vector

    @staticmethod
    def _raw_value(features: FeatureVector, field_name: str) -> float:
        return float(getattr(features, field_name, 0.0))

    @staticmethod
    def _sigmoid(value: float) -> float:
        value = max(-40.0, min(40.0, value))
        return 1.0 / (1.0 + math.exp(-value))

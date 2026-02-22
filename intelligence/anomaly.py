from __future__ import annotations

import math
from dataclasses import dataclass

from .models import FeatureVector

NUMERIC_FIELDS = [
    "permissions_total",
    "suspicious_permissions_count",
    "dangerous_permissions_count",
    "ad_sdk_hits",
    "tracker_hits",
    "suspicious_keyword_hits",
]


@dataclass(slots=True)
class BaselineStats:
    means: dict[str, float]
    stds: dict[str, float]
    sample_size: int


@dataclass(slots=True)
class AnomalyResult:
    score: float
    zmax: float


class ZScoreAnomalyDetector:
    """Simple anomaly detector to bootstrap intelligence without heavy ML deps."""

    def evaluate(self, features: FeatureVector, baseline: BaselineStats | None) -> AnomalyResult | None:
        if baseline is None or baseline.sample_size < 8:
            return None

        z_values: list[float] = []

        for field_name in NUMERIC_FIELDS:
            mean = baseline.means.get(field_name, 0.0)
            std = baseline.stds.get(field_name, 0.0)
            value = float(getattr(features, field_name))

            if std <= 1e-9:
                z = 0.0 if abs(value - mean) < 1e-9 else 3.0
            else:
                z = abs((value - mean) / std)
            z_values.append(z)

        zmax = max(z_values) if z_values else 0.0
        l2 = math.sqrt(sum(z * z for z in z_values))
        score = min(100.0, round((zmax * 18.0) + (l2 * 4.0), 2))
        return AnomalyResult(score=score, zmax=round(zmax, 4))

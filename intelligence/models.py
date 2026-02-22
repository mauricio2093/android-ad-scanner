from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class FeatureVector:
    package_name: str
    installer: str
    install_path: str
    permissions_total: int
    suspicious_permissions_count: int
    dangerous_permissions_count: int
    ad_sdk_hits: int
    tracker_hits: int
    suspicious_keyword_hits: int
    boot_receiver_detected: int
    accessibility_binding_detected: int
    overlay_permission_detected: int
    install_packages_permission_detected: int
    write_settings_detected: int
    apk_hash_present: int = 0
    apk_size_kb: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class IntelligentScanResult:
    scan_id: int | None
    device_id: str
    package_name: str
    timestamp_utc: str
    feature_vector: FeatureVector
    risk_score: float
    risk_level: str
    anomaly_score: float | None
    anomaly_zmax: float | None
    ml_risk_score: float | None = None
    ml_model_version: str | None = None
    component_fingerprint: str | None = None
    reasons: list[str] = field(default_factory=list)
    ioc_matches: list[str] = field(default_factory=list)
    attack_techniques: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "device_id": self.device_id,
            "package_name": self.package_name,
            "timestamp_utc": self.timestamp_utc,
            "feature_vector": self.feature_vector.to_dict(),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "anomaly_score": self.anomaly_score,
            "anomaly_zmax": self.anomaly_zmax,
            "ml_risk_score": self.ml_risk_score,
            "ml_model_version": self.ml_model_version,
            "component_fingerprint": self.component_fingerprint,
            "reasons": list(self.reasons),
            "ioc_matches": list(self.ioc_matches),
            "attack_techniques": list(self.attack_techniques),
        }

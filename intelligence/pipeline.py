from __future__ import annotations

import datetime
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from .attack_mapping import infer_attack_techniques
from .anomaly import ZScoreAnomalyDetector
from .apk_artifact import hash_file_sha256
from .campaigns import (
    build_campaign_dashboard_markdown,
    serialize_campaign_summary,
    summarize_campaigns,
)
from .intel_db import ThreatIntelDB
from .ml_model import SupervisedRiskModel
from .models import FeatureVector, IntelligentScanResult
from .risk_engine import RuleBasedRiskEngine
from .stixlite import build_stix_lite_bundle

DEFAULT_IOC_FILE = Path("config/intel_iocs.json")

AD_TECH_MARKERS = [
    "admob",
    "applovin",
    "unityads",
    "appsflyer",
    "facebook ads",
    "ironsource",
    "chartboost",
    "mintegral",
    "mbridge",
    "tiktokads",
]

TRACKER_MARKERS = [
    "analytics",
    "track",
    "telemetry",
    "fingerprint",
    "referrer",
    "attribution",
]

SUSPICIOUS_KEYWORDS = [
    "accessibility",
    "overlay",
    "autostart",
    "silent",
    "background install",
    "receiver",
    "unknown source",
]

HIGH_RISK_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.WRITE_SETTINGS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_LOGS",
}

DANGEROUS_PERMISSION_PATTERN = re.compile(r"android\.permission\.[A-Z0-9_]+")
EXPORTED_TRUE_PATTERN = re.compile(r"exported\\s*=\\s*true", re.IGNORECASE)


class IntelligentScanPipeline:
    def __init__(
        self,
        db_path: Path,
        adb_timeout: int = 90,
    ) -> None:
        self.db = ThreatIntelDB(db_path)
        self.risk_engine = RuleBasedRiskEngine()
        self.anomaly_detector = ZScoreAnomalyDetector()
        self.adb_timeout = adb_timeout
        self.ml_model: SupervisedRiskModel | None = None
        self._load_latest_ml_model()

    def _load_latest_ml_model(self) -> None:
        row = self.db.get_latest_ml_model(SupervisedRiskModel.model_name)
        if row is None:
            self.ml_model = None
            return

        try:
            payload = json.loads(row["model_payload_json"])
            self.ml_model = SupervisedRiskModel.from_dict(payload)
        except Exception:
            self.ml_model = None

    def sync_iocs_from_file(self, ioc_file: Path | None = None) -> int:
        ioc_file = ioc_file or DEFAULT_IOC_FILE
        if not ioc_file.exists():
            ioc_file.parent.mkdir(parents=True, exist_ok=True)
            ioc_file.write_text(
                json.dumps(
                    {
                        "iocs": [
                            {
                                "ioc_type": "keyword",
                                "value": "com.fake.system.updater",
                                "severity": 9,
                                "confidence": 0.9,
                                "source": "local_seed",
                                "active": True,
                            },
                            {
                                "ioc_type": "keyword",
                                "value": "silentinstall",
                                "severity": 8,
                                "confidence": 0.8,
                                "source": "local_seed",
                                "active": True,
                            },
                            {
                                "ioc_type": "regex",
                                "value": "android\\.permission\\.BIND_ACCESSIBILITY_SERVICE",
                                "severity": 8,
                                "confidence": 0.85,
                                "source": "local_seed",
                                "active": True,
                            },
                        ]
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

        data = json.loads(ioc_file.read_text(encoding="utf-8"))
        iocs = data.get("iocs", []) if isinstance(data, dict) else []
        return self.db.upsert_iocs(iocs)

    def scan_package(
        self,
        device_id: str,
        package_name: str,
    ) -> IntelligentScanResult:
        snapshot = self._collect_snapshot(device_id=device_id, package_name=package_name)
        features = self._build_features(snapshot=snapshot, package_name=package_name)
        component_summary = self._extract_component_summary(snapshot=snapshot)
        component_fingerprint = self._build_component_fingerprint(
            package_name=package_name,
            snapshot=snapshot,
            component_summary=component_summary,
        )
        ioc_matches = self._match_iocs(snapshot)
        attack_techniques = infer_attack_techniques(
            features=features,
            dumpsys_text=str(snapshot.get("dumpsys_package", "")),
        )

        risk = self.risk_engine.evaluate(features, ioc_matches=ioc_matches)
        baseline = self.db.load_baseline()
        anomaly = self.anomaly_detector.evaluate(features, baseline)

        ml_score: float | None = None
        model_version: str | None = None
        if self.ml_model is not None:
            ml_prob = self.ml_model.predict_proba(features)
            ml_score = round(ml_prob * 100.0, 2)
            model_version = self.ml_model.version

        if ml_score is not None:
            blended = (0.65 * risk.score) + (0.35 * ml_score)
            risk_score = round(min(100.0, blended), 2)
            reasons = list(risk.reasons) + [
                f"Modelo ML ({model_version}) sugiere riesgo {ml_score}",
            ]
        else:
            risk_score = risk.score
            reasons = list(risk.reasons)

        if attack_techniques:
            reasons.append(f"Mapeo ATT&CK Mobile inferido: {len(attack_techniques)} tecnicas")

        if anomaly and anomaly.score >= 70:
            risk_score = min(100.0, round(risk_score + 12.0, 2))
            reasons.append(f"Anomalia estadistica alta (score={anomaly.score}, zmax={anomaly.zmax})")

        risk_level = self.risk_engine._score_to_level(risk_score)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

        result = IntelligentScanResult(
            scan_id=None,
            device_id=device_id,
            package_name=package_name,
            timestamp_utc=timestamp,
            feature_vector=features,
            risk_score=risk_score,
            risk_level=risk_level,
            anomaly_score=anomaly.score if anomaly else None,
            anomaly_zmax=anomaly.zmax if anomaly else None,
            ml_risk_score=ml_score,
            ml_model_version=model_version,
            component_fingerprint=component_fingerprint,
            reasons=reasons,
            ioc_matches=ioc_matches,
            attack_techniques=attack_techniques,
        )

        snapshot["component_summary"] = component_summary
        snapshot["component_fingerprint"] = component_fingerprint
        snapshot["attack_techniques"] = attack_techniques
        scan_id = self.db.store_scan(result=result, raw_snapshot=snapshot)
        result.scan_id = scan_id
        return result

    def rebuild_baseline(self, max_rows: int = 500) -> int:
        return self.db.rebuild_baseline_from_history(max_rows=max_rows)

    def label_latest_scan_for_package(self, package_name: str, label: int, source: str = "gui") -> int | None:
        scan_id = self.db.get_latest_scan_id_for_package(package_name)
        if scan_id is None:
            return None
        self.db.set_scan_label(scan_id, label=label, source=source)
        return scan_id

    def label_scan(self, scan_id: int, label: int, source: str = "cli") -> None:
        self.db.set_scan_label(scan_id=scan_id, label=label, source=source)

    def get_recent_scans(self, limit: int = 20) -> list[dict]:
        rows = self.db.get_recent_scans(limit=limit)
        output: list[dict] = []
        for row in rows:
            output.append(
                {
                    "id": int(row["id"]),
                    "created_at": str(row["created_at"]),
                    "device_id": str(row["device_id"]),
                    "package_name": str(row["package_name"]),
                    "risk_score": float(row["risk_score"]),
                    "risk_level": str(row["risk_level"]),
                    "label": None if row["label"] is None else int(row["label"]),
                }
            )
        return output

    def export_stix_lite(
        self,
        *,
        output_path: Path | None = None,
        limit: int = 100,
        scan_ids: list[int] | None = None,
    ) -> dict:
        if scan_ids:
            records = self.db.get_scan_records_by_ids(scan_ids)
        else:
            records = self.db.get_scan_records(limit=limit)

        bundle = build_stix_lite_bundle(records, source_name="android-ad-scanner")
        if output_path is not None:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
        return bundle

    def analyze_campaigns(self, *, limit: int = 2000, min_cluster_size: int = 2) -> dict:
        records = self.db.get_scan_records(limit=limit)
        return summarize_campaigns(records, min_cluster_size=min_cluster_size)

    def export_campaign_dashboard(
        self,
        *,
        output_path: Path,
        limit: int = 2000,
        min_cluster_size: int = 2,
        top_n: int = 20,
    ) -> dict:
        summary = self.analyze_campaigns(limit=limit, min_cluster_size=min_cluster_size)
        markdown = build_campaign_dashboard_markdown(summary, top_n=top_n)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(markdown, encoding="utf-8")

        json_out_path = output_path.with_suffix(".json")
        json_out_path.write_text(serialize_campaign_summary(summary), encoding="utf-8")

        return {
            "generated_at": summary.get("generated_at"),
            "clusters_count": len(list(summary.get("clusters", []))),
            "total_scans": int(summary.get("total_scans", 0)),
            "markdown_output": str(output_path),
            "json_output": str(json_out_path),
        }

    def train_supervised_model(self, min_samples: int = 20, max_rows: int = 5000) -> dict:
        labeled_rows = self.db.get_labeled_feature_rows(max_rows=max_rows)
        if len(labeled_rows) < min_samples:
            raise ValueError(
                f"Muestras etiquetadas insuficientes: {len(labeled_rows)} (minimo requerido: {min_samples})"
            )

        dataset: list[tuple[FeatureVector, int]] = []
        for payload, label in labeled_rows:
            feature = FeatureVector(
                package_name=str(payload.get("package_name", "unknown")),
                installer=str(payload.get("installer", "unknown")),
                install_path=str(payload.get("install_path", "unknown")),
                permissions_total=int(payload.get("permissions_total", 0)),
                suspicious_permissions_count=int(payload.get("suspicious_permissions_count", 0)),
                dangerous_permissions_count=int(payload.get("dangerous_permissions_count", 0)),
                ad_sdk_hits=int(payload.get("ad_sdk_hits", 0)),
                tracker_hits=int(payload.get("tracker_hits", 0)),
                suspicious_keyword_hits=int(payload.get("suspicious_keyword_hits", 0)),
                boot_receiver_detected=int(payload.get("boot_receiver_detected", 0)),
                accessibility_binding_detected=int(payload.get("accessibility_binding_detected", 0)),
                overlay_permission_detected=int(payload.get("overlay_permission_detected", 0)),
                install_packages_permission_detected=int(payload.get("install_packages_permission_detected", 0)),
                write_settings_detected=int(payload.get("write_settings_detected", 0)),
                apk_hash_present=int(payload.get("apk_hash_present", 0)),
                apk_size_kb=float(payload.get("apk_size_kb", 0.0)),
            )
            dataset.append((feature, int(label)))

        model = SupervisedRiskModel()
        metrics = model.fit(dataset)
        self.db.store_ml_model(
            model_name=model.model_name,
            model_version=model.version,
            model_payload=model.to_dict(),
            metrics_payload=metrics.to_dict(),
            trained_samples=metrics.samples,
        )
        self.ml_model = model

        return {
            "model_name": model.model_name,
            "model_version": model.version,
            "trained_samples": metrics.samples,
            "metrics": metrics.to_dict(),
        }

    def _collect_snapshot(self, device_id: str, package_name: str) -> dict:
        dumpsys = self._run_adb(["-s", device_id, "shell", "dumpsys", "package", package_name])
        pm_path = self._run_adb(["-s", device_id, "shell", "pm", "path", package_name])
        installer = self._run_adb(["-s", device_id, "shell", "pm", "list", "packages", "-i", package_name])
        apk_artifact = self._extract_apk_artifact(device_id=device_id, pm_path_output=pm_path)

        return {
            "dumpsys_package": dumpsys,
            "pm_path": pm_path,
            "pm_installer": installer,
            **apk_artifact,
        }

    def _extract_apk_artifact(self, device_id: str, pm_path_output: str) -> dict:
        remote_paths: list[str] = []
        for line in pm_path_output.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                remote_paths.append(line.split("package:", 1)[1].strip())

        if not remote_paths:
            return {
                "apk_remote_path": "",
                "apk_sha256": "",
                "apk_size_bytes": 0,
                "apk_pull_error": "No se encontro ruta APK desde pm path",
            }

        remote_apk = remote_paths[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            local_apk = Path(tmpdir) / "base.apk"
            try:
                subprocess.run(
                    ["adb", "-s", device_id, "pull", remote_apk, str(local_apk)],
                    check=True,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=max(self.adb_timeout, 180),
                )
                sha256 = hash_file_sha256(local_apk)
                size_bytes = local_apk.stat().st_size
                return {
                    "apk_remote_path": remote_apk,
                    "apk_sha256": sha256,
                    "apk_size_bytes": size_bytes,
                    "apk_pull_error": "",
                }
            except Exception as exc:
                return {
                    "apk_remote_path": remote_apk,
                    "apk_sha256": "",
                    "apk_size_bytes": 0,
                    "apk_pull_error": str(exc),
                }

    def _run_adb(self, args: Sequence[str]) -> str:
        result = subprocess.run(
            ["adb", *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.adb_timeout,
        )
        return result.stdout

    def _build_features(self, snapshot: dict, package_name: str) -> FeatureVector:
        dumpsys = snapshot.get("dumpsys_package", "")
        pm_path = snapshot.get("pm_path", "")
        installer_raw = snapshot.get("pm_installer", "")

        permissions = set(DANGEROUS_PERMISSION_PATTERN.findall(dumpsys))
        suspicious_permissions = [p for p in permissions if p in HIGH_RISK_PERMISSIONS]

        installer = "unknown"
        installer_match = re.search(r"installer=([^\s]+)", installer_raw)
        if installer_match:
            installer = installer_match.group(1).strip()

        path_match = re.search(r"package:(.+)", pm_path)
        install_path = path_match.group(1).strip() if path_match else "unknown"

        lowered = dumpsys.lower()
        ad_sdk_hits = sum(1 for marker in AD_TECH_MARKERS if marker in lowered)
        tracker_hits = sum(1 for marker in TRACKER_MARKERS if marker in lowered)
        suspicious_keyword_hits = sum(1 for marker in SUSPICIOUS_KEYWORDS if marker in lowered)

        apk_sha256 = str(snapshot.get("apk_sha256", "")).strip()
        apk_size_bytes = int(snapshot.get("apk_size_bytes", 0) or 0)

        return FeatureVector(
            package_name=package_name,
            installer=installer,
            install_path=install_path,
            permissions_total=len(permissions),
            suspicious_permissions_count=len(suspicious_permissions),
            dangerous_permissions_count=len(permissions),
            ad_sdk_hits=ad_sdk_hits,
            tracker_hits=tracker_hits,
            suspicious_keyword_hits=suspicious_keyword_hits,
            boot_receiver_detected=1 if "receive_boot_completed" in lowered else 0,
            accessibility_binding_detected=1 if "bind_accessibility_service" in lowered else 0,
            overlay_permission_detected=1 if "system_alert_window" in lowered else 0,
            install_packages_permission_detected=1 if "request_install_packages" in lowered else 0,
            write_settings_detected=1 if "write_settings" in lowered else 0,
            apk_hash_present=1 if apk_sha256 else 0,
            apk_size_kb=round(apk_size_bytes / 1024.0, 2) if apk_size_bytes > 0 else 0.0,
        )

    def _match_iocs(self, snapshot: dict) -> list[str]:
        corpus = "\n".join(
            [
                str(snapshot.get("dumpsys_package", "")),
                str(snapshot.get("pm_path", "")),
                str(snapshot.get("pm_installer", "")),
            ]
        ).lower()

        apk_sha256 = str(snapshot.get("apk_sha256", "")).strip().lower()

        rows = self.db.get_active_iocs()
        matches: list[str] = []

        for row in rows:
            ioc_type = str(row["ioc_type"]).strip().lower()
            value = str(row["value"]).strip().lower()
            if not value:
                continue

            if ioc_type in {"hash_sha256", "sha256"}:
                if apk_sha256 and value == apk_sha256:
                    matches.append(f"sha256:{value}")
                continue

            if ioc_type == "regex":
                try:
                    if re.search(value, corpus, flags=re.IGNORECASE):
                        matches.append(value)
                except re.error:
                    continue
            else:
                if value in corpus:
                    matches.append(value)

        return matches

    def _extract_component_summary(self, snapshot: dict) -> dict[str, int]:
        dumpsys = str(snapshot.get("dumpsys_package", ""))
        lowered = dumpsys.lower()
        lines = dumpsys.splitlines()

        receiver_hits = sum(1 for line in lines if "receiver" in line.lower())
        service_hits = sum(1 for line in lines if "service" in line.lower())
        activity_hits = sum(1 for line in lines if "activity" in line.lower())
        provider_hits = sum(1 for line in lines if "provider" in line.lower())
        exported_true_hits = len(EXPORTED_TRUE_PATTERN.findall(dumpsys))

        return {
            "receiver_hits": int(receiver_hits),
            "service_hits": int(service_hits),
            "activity_hits": int(activity_hits),
            "provider_hits": int(provider_hits),
            "exported_true_hits": int(exported_true_hits),
            "has_boot_receiver": 1 if "receive_boot_completed" in lowered else 0,
            "has_notification_listener": 1 if "bind_notification_listener_service" in lowered else 0,
            "has_accessibility_binding": 1 if "bind_accessibility_service" in lowered else 0,
        }

    def _build_component_fingerprint(
        self,
        *,
        package_name: str,
        snapshot: dict,
        component_summary: dict[str, int],
    ) -> str:
        dumpsys = str(snapshot.get("dumpsys_package", ""))
        permissions = sorted(set(DANGEROUS_PERMISSION_PATTERN.findall(dumpsys)))
        payload = {
            "package_name": package_name,
            "permissions": permissions,
            "component_summary": component_summary,
            "apk_sha256": str(snapshot.get("apk_sha256", "")),
            "apk_remote_path": str(snapshot.get("apk_remote_path", "")),
        }
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

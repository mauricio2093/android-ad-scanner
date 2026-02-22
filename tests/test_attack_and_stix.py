import json
import tempfile
import unittest
from pathlib import Path

from intelligence.attack_mapping import infer_attack_techniques
from intelligence.intel_db import ThreatIntelDB
from intelligence.models import FeatureVector, IntelligentScanResult
from intelligence.pipeline import IntelligentScanPipeline
from intelligence.stixlite import build_stix_lite_bundle


class AttackAndStixTests(unittest.TestCase):
    def test_attack_mapping_inference(self):
        features = FeatureVector(
            package_name="com.example.mal",
            installer="unknown",
            install_path="/data/app/com.example.mal/base.apk",
            permissions_total=8,
            suspicious_permissions_count=3,
            dangerous_permissions_count=8,
            ad_sdk_hits=2,
            tracker_hits=2,
            suspicious_keyword_hits=2,
            boot_receiver_detected=1,
            accessibility_binding_detected=1,
            overlay_permission_detected=1,
            install_packages_permission_detected=1,
            write_settings_detected=1,
            apk_hash_present=1,
            apk_size_kb=1024.0,
        )
        dumpsys = "BIND_NOTIFICATION_LISTENER_SERVICE and RECEIVE_BOOT_COMPLETED"
        techniques = infer_attack_techniques(features, dumpsys)
        ids = {item["id"] for item in techniques}
        self.assertIn("T1453", ids)
        self.assertIn("T1624.001", ids)
        self.assertIn("T1417.002", ids)

    def test_build_stix_bundle(self):
        records = [
            {
                "id": 7,
                "created_at": "2026-02-22T20:00:00+00:00",
                "device_id": "emulator-5554",
                "package_name": "com.example.mal",
                "risk_score": 91.0,
                "risk_level": "CRITICAL",
                "features": {"a": 1},
                "reasons": ["reason1", "reason2"],
                "ioc_matches": ["silentinstall"],
                "raw_snapshot": {
                    "apk_sha256": "a" * 64,
                },
                "attack_techniques": [
                    {"id": "T1453", "name": "Abuse Accessibility Features", "tactic": "Privilege Escalation", "confidence": "high"}
                ],
            }
        ]
        bundle = build_stix_lite_bundle(records)
        self.assertEqual(bundle["type"], "bundle")
        self.assertGreater(len(bundle["objects"]), 3)

    def test_pipeline_export_stix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "intel.db"
            pipeline = IntelligentScanPipeline(db_path=db_path)

            fv = FeatureVector(
                package_name="com.example.safe",
                installer="com.android.vending",
                install_path="/data/app/com.example.safe/base.apk",
                permissions_total=2,
                suspicious_permissions_count=0,
                dangerous_permissions_count=2,
                ad_sdk_hits=0,
                tracker_hits=0,
                suspicious_keyword_hits=0,
                boot_receiver_detected=0,
                accessibility_binding_detected=0,
                overlay_permission_detected=0,
                install_packages_permission_detected=0,
                write_settings_detected=0,
                apk_hash_present=0,
                apk_size_kb=0.0,
            )
            result = IntelligentScanResult(
                scan_id=None,
                device_id="emulator-5554",
                package_name=fv.package_name,
                timestamp_utc="2026-02-22T22:00:00+00:00",
                feature_vector=fv,
                risk_score=10.0,
                risk_level="LOW",
                anomaly_score=None,
                anomaly_zmax=None,
                reasons=["test"],
                ioc_matches=[],
                attack_techniques=[],
            )
            raw = {"apk_sha256": "", "attack_techniques": []}
            _ = pipeline.db.store_scan(result, raw)

            out_path = Path(tmpdir) / "bundle.json"
            bundle = pipeline.export_stix_lite(output_path=out_path, limit=10)
            self.assertTrue(out_path.exists())
            loaded = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["type"], "bundle")
            self.assertEqual(bundle["type"], "bundle")


if __name__ == "__main__":
    unittest.main()

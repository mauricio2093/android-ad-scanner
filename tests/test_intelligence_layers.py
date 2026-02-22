import json
import tempfile
import unittest
from pathlib import Path

from intelligence.anomaly import BaselineStats, ZScoreAnomalyDetector
from intelligence.intel_db import ThreatIntelDB
from intelligence.models import FeatureVector, IntelligentScanResult
from intelligence.risk_engine import RuleBasedRiskEngine


class IntelligenceLayerTests(unittest.TestCase):
    def _feature_vector(self) -> FeatureVector:
        return FeatureVector(
            package_name="com.example.test",
            installer="com.android.vending",
            install_path="/data/app/com.example.test/base.apk",
            permissions_total=12,
            suspicious_permissions_count=3,
            dangerous_permissions_count=12,
            ad_sdk_hits=5,
            tracker_hits=3,
            suspicious_keyword_hits=2,
            boot_receiver_detected=1,
            accessibility_binding_detected=1,
            overlay_permission_detected=1,
            install_packages_permission_detected=1,
            write_settings_detected=1,
        )

    def test_risk_engine_high(self):
        engine = RuleBasedRiskEngine()
        result = engine.evaluate(self._feature_vector(), ioc_matches=["silentinstall"])
        self.assertGreaterEqual(result.score, 75)
        self.assertEqual(result.level, "CRITICAL")

    def test_anomaly_detector(self):
        baseline = BaselineStats(
            means={
                "permissions_total": 4,
                "suspicious_permissions_count": 0,
                "dangerous_permissions_count": 4,
                "ad_sdk_hits": 1,
                "tracker_hits": 1,
                "suspicious_keyword_hits": 0,
            },
            stds={
                "permissions_total": 1,
                "suspicious_permissions_count": 0.5,
                "dangerous_permissions_count": 1,
                "ad_sdk_hits": 0.5,
                "tracker_hits": 0.5,
                "suspicious_keyword_hits": 0.5,
            },
            sample_size=25,
        )

        detector = ZScoreAnomalyDetector()
        anomaly = detector.evaluate(self._feature_vector(), baseline)
        self.assertIsNotNone(anomaly)
        assert anomaly is not None
        self.assertGreater(anomaly.score, 50)

    def test_db_store_and_baseline(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "intel.db"
            db = ThreatIntelDB(db_path)

            fv = self._feature_vector()
            result = IntelligentScanResult(
                scan_id=None,
                device_id="emulator-5554",
                package_name=fv.package_name,
                timestamp_utc="2026-02-22T20:00:00",
                feature_vector=fv,
                risk_score=88.0,
                risk_level="CRITICAL",
                anomaly_score=72.0,
                anomaly_zmax=3.2,
                reasons=["test"],
                ioc_matches=["silentinstall"],
            )

            scan_id = db.store_scan(result, raw_snapshot={"dumpsys_package": "abc"})
            self.assertGreater(scan_id, 0)

            rebuilt = db.rebuild_baseline_from_history()
            self.assertEqual(rebuilt, 1)

            baseline = db.load_baseline()
            self.assertIsNotNone(baseline)

            latest_scan = db.get_latest_scan_id_for_package(fv.package_name)
            self.assertEqual(latest_scan, scan_id)
            db.set_scan_label(scan_id, label=1, source="unit-test")
            labeled_rows = db.get_labeled_feature_rows(max_rows=10)
            self.assertEqual(len(labeled_rows), 1)

    def test_ioc_upsert(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = ThreatIntelDB(Path(tmpdir) / "intel.db")
            n = db.upsert_iocs(
                [
                    {
                        "ioc_type": "keyword",
                        "value": "silentinstall",
                        "severity": 8,
                        "confidence": 0.8,
                        "source": "unit-test",
                        "active": True,
                    }
                ]
            )
            self.assertEqual(n, 1)
            rows = db.get_active_iocs()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["value"], "silentinstall")


if __name__ == "__main__":
    unittest.main()

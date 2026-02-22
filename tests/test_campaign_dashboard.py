import json
import tempfile
import unittest
from pathlib import Path

from intelligence.campaigns import build_campaign_dashboard_markdown, summarize_campaigns
from intelligence.models import FeatureVector, IntelligentScanResult
from intelligence.pipeline import IntelligentScanPipeline


class CampaignDashboardTests(unittest.TestCase):
    def test_summarize_campaigns(self):
        records = [
            {
                "id": 1,
                "created_at": "2026-02-22T10:00:00+00:00",
                "device_id": "A",
                "package_name": "com.bad.one",
                "risk_score": 84.0,
                "risk_level": "HIGH",
                "label": 1,
                "ioc_matches": ["silentinstall"],
                "attack_techniques": [{"id": "T1453"}],
                "raw_snapshot": {
                    "apk_sha256": "aa" * 32,
                    "component_fingerprint": "fp1",
                },
            },
            {
                "id": 2,
                "created_at": "2026-02-22T18:00:00+00:00",
                "device_id": "B",
                "package_name": "com.bad.clone",
                "risk_score": 91.0,
                "risk_level": "CRITICAL",
                "label": 1,
                "ioc_matches": ["silentinstall", "regexhit"],
                "attack_techniques": [{"id": "T1453"}, {"id": "T1624.001"}],
                "raw_snapshot": {
                    "apk_sha256": "aa" * 32,
                    "component_fingerprint": "fp1",
                },
            },
        ]

        summary = summarize_campaigns(records, min_cluster_size=2)
        self.assertEqual(summary["total_scans"], 2)
        self.assertEqual(len(summary["clusters"]), 1)
        cluster = summary["clusters"][0]
        self.assertEqual(cluster["device_count"], 2)
        self.assertGreaterEqual(cluster["campaign_score"], 60)

    def test_build_campaign_dashboard_markdown(self):
        summary = {
            "generated_at": "2026-02-22T23:00:00+00:00",
            "total_scans": 10,
            "high_risk_scans": 5,
            "global_device_count": 4,
            "global_package_count": 7,
            "clusters": [
                {
                    "campaign_id": "camp-123",
                    "campaign_score": 88.0,
                    "campaign_level": "CRITICAL",
                    "scan_count": 3,
                    "device_count": 2,
                    "package_count": 2,
                    "trend": "growing",
                    "cluster_key": "sha256:abc",
                    "avg_risk": 80.0,
                    "max_risk": 95.0,
                    "devices": ["A", "B"],
                    "packages": ["p1", "p2"],
                    "attack_techniques": ["T1453"],
                    "ioc_density": 1.2,
                    "ioc_matches_total": 4,
                    "first_seen": "2026-02-22T01:00:00+00:00",
                    "last_seen": "2026-02-22T21:00:00+00:00",
                    "scan_ids": [1, 2, 3],
                    "scans_last_24h": 2,
                    "scans_prev_24h": 1,
                }
            ],
        }
        markdown = build_campaign_dashboard_markdown(summary)
        self.assertIn("Campaign Correlation Dashboard", markdown)
        self.assertIn("camp-123", markdown)

    def test_pipeline_export_campaign_dashboard(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "intel.db"
            pipeline = IntelligentScanPipeline(db_path=db_path)

            fv = FeatureVector(
                package_name="com.bad.one",
                installer="unknown",
                install_path="/data/app/base.apk",
                permissions_total=8,
                suspicious_permissions_count=3,
                dangerous_permissions_count=8,
                ad_sdk_hits=4,
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
            result = IntelligentScanResult(
                scan_id=None,
                device_id="device-1",
                package_name="com.bad.one",
                timestamp_utc="2026-02-22T20:00:00+00:00",
                feature_vector=fv,
                risk_score=86.0,
                risk_level="HIGH",
                anomaly_score=40.0,
                anomaly_zmax=1.5,
                reasons=["r1"],
                ioc_matches=["silentinstall"],
                component_fingerprint="fp-camp",
                attack_techniques=[{"id": "T1453", "name": "Abuse Accessibility Features"}],
            )
            raw = {
                "apk_sha256": "",
                "component_fingerprint": "fp-camp",
                "attack_techniques": [{"id": "T1453", "name": "Abuse Accessibility Features"}],
            }
            pipeline.db.store_scan(result, raw)

            out_path = Path(tmpdir) / "campaign_dashboard.md"
            summary = pipeline.export_campaign_dashboard(
                output_path=out_path,
                limit=50,
                min_cluster_size=1,
                top_n=10,
            )
            self.assertTrue(out_path.exists())
            self.assertTrue((Path(tmpdir) / "campaign_dashboard.json").exists())
            self.assertGreaterEqual(int(summary["clusters_count"]), 1)

            payload = json.loads((Path(tmpdir) / "campaign_dashboard.json").read_text(encoding="utf-8"))
            self.assertIn("clusters", payload)


if __name__ == "__main__":
    unittest.main()

import tempfile
import unittest
from pathlib import Path

from intelligence.apk_artifact import hash_file_sha256
from intelligence.ml_model import SupervisedRiskModel
from intelligence.models import FeatureVector


class MLAndApkTests(unittest.TestCase):
    def _row(self, suspicious: int, ad_hits: int, label: int) -> tuple[FeatureVector, int]:
        return (
            FeatureVector(
                package_name="com.example.app",
                installer="com.android.vending",
                install_path="/data/app/base.apk",
                permissions_total=10 + suspicious,
                suspicious_permissions_count=suspicious,
                dangerous_permissions_count=10 + suspicious,
                ad_sdk_hits=ad_hits,
                tracker_hits=ad_hits // 2,
                suspicious_keyword_hits=suspicious,
                boot_receiver_detected=1 if suspicious > 1 else 0,
                accessibility_binding_detected=1 if suspicious > 2 else 0,
                overlay_permission_detected=1 if suspicious > 0 else 0,
                install_packages_permission_detected=1 if suspicious > 1 else 0,
                write_settings_detected=1 if suspicious > 1 else 0,
                apk_hash_present=1,
                apk_size_kb=2048.0,
            ),
            label,
        )

    def test_model_fit_predict(self):
        rows = [
            self._row(0, 0, 0),
            self._row(0, 1, 0),
            self._row(1, 1, 0),
            self._row(1, 2, 0),
            self._row(3, 4, 1),
            self._row(4, 5, 1),
            self._row(5, 6, 1),
            self._row(4, 4, 1),
            self._row(0, 0, 0),
            self._row(5, 6, 1),
        ]

        model = SupervisedRiskModel()
        metrics = model.fit(rows, epochs=220, learning_rate=0.07)
        self.assertGreater(metrics.accuracy, 0.7)

        benign_prob = model.predict_proba(self._row(0, 0, 0)[0])
        malicious_prob = model.predict_proba(self._row(5, 6, 1)[0])
        self.assertLess(benign_prob, malicious_prob)

    def test_sha256_hash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            sample = Path(tmpdir) / "sample.bin"
            sample.write_bytes(b"android-ad-scanner")
            digest = hash_file_sha256(sample)
            self.assertEqual(len(digest), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in digest))


if __name__ == "__main__":
    unittest.main()

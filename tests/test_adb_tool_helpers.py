import unittest

from adb_automation_tool import (
    extract_device_ids,
    filter_lines_with_pattern,
    is_safe_keyword,
    is_valid_package_name,
)


class ADBToolHelperTests(unittest.TestCase):
    def test_valid_package_name(self):
        self.assertTrue(is_valid_package_name("com.empresa.segura"))
        self.assertTrue(is_valid_package_name("org.example.tool_1"))

    def test_invalid_package_name(self):
        self.assertFalse(is_valid_package_name("rm -rf /"))
        self.assertFalse(is_valid_package_name("com"))
        self.assertFalse(is_valid_package_name("com..test"))

    def test_safe_keyword(self):
        self.assertTrue(is_safe_keyword("analytics"))
        self.assertTrue(is_safe_keyword("app.track-v2"))
        self.assertFalse(is_safe_keyword("ad | powershell"))
        self.assertFalse(is_safe_keyword("a"))

    def test_extract_device_ids(self):
        raw = (
            "List of devices attached\n"
            "emulator-5554\tdevice\n"
            "ZX1G22\toffline\n"
            "RF8N123\tdevice\n"
        )
        self.assertEqual(extract_device_ids(raw), ["emulator-5554", "RF8N123"])

    def test_filter_lines_with_pattern(self):
        content = "one\nPermission: CAMERA\npermission: RECORD_AUDIO\nnone\n"
        filtered = filter_lines_with_pattern(content, r"permission")
        self.assertIn("Permission: CAMERA", filtered)
        self.assertIn("permission: RECORD_AUDIO", filtered)
        self.assertNotIn("one", filtered)


if __name__ == "__main__":
    unittest.main()

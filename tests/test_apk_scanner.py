import unittest
from app.utils.apk_scanner import scan_apk

class TestAPKScanner(unittest.TestCase):
    def test_scan_apk(self):
        apk_file = "tests/test.apk"
        result = scan_apk(apk_file)
        self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()

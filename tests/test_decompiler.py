import unittest
from app.utils.decompiler import decompile_apk

class TestDecompiler(unittest.TestCase):
    def test_decompile(self):
        apk_file = "tests/test.apk"
        result = decompile_apk(apk_file)
        self.assertTrue(result.endswith('_decompiled'))

if __name__ == '__main__':
    unittest.main()

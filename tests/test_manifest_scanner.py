import unittest
from manifest_scanner.manifest_analysis import analyze_manifest

class ManifestScannerTestCase(unittest.TestCase):
    def test_manifest_not_found(self):
        """
        Test when the manifest file does not exist.
        """
        manifest_path = "non_existent/AndroidManifest.xml"
        issues = analyze_manifest(manifest_path)
        self.assertEqual(len(issues), 0)
        self.assertIn("Manifest file not found", issues)

    def test_analyze_manifest_permissions(self):
        """
        Test analysis of dangerous permissions in the manifest file.
        """
        manifest_path = "test_files/AndroidManifest_with_dangerous_permissions.xml"
        issues = analyze_manifest(manifest_path)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any(issue['issue_type'] == 'Permission' for issue in issues))

    def test_analyze_manifest_debuggable(self):
        """
        Test analysis of the debuggable attribute in the manifest file.
        """
        manifest_path = "test_files/AndroidManifest_debuggable.xml"
        issues = analyze_manifest(manifest_path)
        self.assertGreater(len(issues), 0)
        self.assertTrue(any(issue['issue_type'] == 'Configuration' and 'debuggable' in issue['issue_detail'] for issue in issues))

if __name__ == '__main__':
    unittest.main()

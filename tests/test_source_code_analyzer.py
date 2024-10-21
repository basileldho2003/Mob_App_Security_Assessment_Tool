import unittest
import os
from source_code_analyzer.source_code_analysis import analyze_source_code

class SourceCodeAnalyzerTestCase(unittest.TestCase):
    def setUp(self):
        """
        Set up the test source code directory.
        """
        self.source_code_dir = "test_files/source_code"
        if not os.path.exists(self.source_code_dir):
            os.makedirs(self.source_code_dir)

        # Create a test Java file
        self.test_java_file_path = os.path.join(self.source_code_dir, "TestClass.java")
        with open(self.test_java_file_path, "w") as f:
            f.write("""
                public class TestClass {
                    public static void main(String[] args) {
                        System.out.println("Hello, World!");
                    }
                }
            """)

    def tearDown(self):
        """
        Remove test files after each test.
        """
        if os.path.exists(self.test_java_file_path):
            os.remove(self.test_java_file_path)
        if os.path.exists(self.source_code_dir):
            os.rmdir(self.source_code_dir)

    def test_analyze_source_code(self):
        """
        Test the source code analysis using Semgrep.
        """
        issues = analyze_source_code(self.source_code_dir)
        # Since this is a basic Java file, we expect no issues to be found
        self.assertEqual(len(issues), 0)

if __name__ == '__main__':
    unittest.main()
import unittest
import os
from report_generator.html_report import generate_html_report
from report_generator.pdf_report import generate_pdf_report

class ReportGeneratorTestCase(unittest.TestCase):
    def setUp(self):
        """
        Set up test files and paths for HTML and PDF report generation.
        """
        self.html_output_path = "test_output/report.html"
        self.pdf_output_path = "test_output/report.pdf"
        self.report_data = {
            'title': 'Security Scan Report',
            'date': '2024-10-01',
            'summary': 'Summary of scan results',
            'issues': [
                {'issue_type': 'Permission', 'detail': 'Potentially dangerous permission requested: INTERNET', 'severity': 'medium'},
                {'issue_type': 'Configuration', 'detail': 'Application is set to be debuggable, which poses a security risk.', 'severity': 'high'}
            ]
        }
        if not os.path.exists("test_output"):
            os.makedirs("test_output")

    def tearDown(self):
        """
        Remove test files after each test.
        """
        if os.path.exists(self.html_output_path):
            os.remove(self.html_output_path)
        if os.path.exists(self.pdf_output_path):
            os.remove(self.pdf_output_path)

    def test_generate_html_report(self):
        """
        Test HTML report generation.
        """
        generate_html_report(self.html_output_path, self.report_data)
        self.assertTrue(os.path.exists(self.html_output_path))

    def test_generate_pdf_report(self):
        """
        Test PDF report generation from an existing HTML report.
        """
        # First generate the HTML report
        generate_html_report(self.html_output_path, self.report_data)
        # Then generate the PDF report from the HTML report
        generate_pdf_report(self.html_output_path, self.pdf_output_path)
        self.assertTrue(os.path.exists(self.pdf_output_path))

if __name__ == '__main__':
    unittest.main()

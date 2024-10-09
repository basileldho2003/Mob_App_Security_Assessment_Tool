import os
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class WebViewSecurityScanner:
    def __init__(self, source_code_dir):
        self.source_code_dir = source_code_dir

    def analyze_files(self):
        """
        Analyzes Java source code files for insecure WebView implementations.
        """
        if not os.path.exists(self.source_code_dir):
            logger.error(f"Source code directory not found at {self.source_code_dir}")
            raise FileNotFoundError(f"Source code directory not found at {self.source_code_dir}")

        for root, _, files in os.walk(self.source_code_dir):
            for file in files:
                if file.endswith(".java"):
                    file_path = os.path.join(root, file)
                    self.analyze_file(file_path)

    def analyze_file(self, file_path):
        """
        Analyzes a single Java source code file for insecure WebView configurations.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

                # Example checks for insecure WebView configurations
                self.check_javascript_enabled(file_path, content)
                self.check_unvalidated_urls(file_path, content)
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")

    def check_javascript_enabled(self, file_path, content):
        """
        Checks if JavaScript is enabled in WebView without proper validation.
        """
        if "setJavaScriptEnabled(true)" in content:
            logger.warning(f"JavaScript is enabled in WebView in {file_path} without proper validation.")

    def check_unvalidated_urls(self, file_path, content):
        """
        Checks for unvalidated URL loading in WebView.
        """
        if re.search(r'loadUrl\s*\(\s*"http://', content):
            logger.warning(f"Unvalidated HTTP URL loading found in WebView in {file_path}.")

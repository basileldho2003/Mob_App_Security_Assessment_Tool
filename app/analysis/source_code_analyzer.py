import os
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SourceCodeAnalyzer:
    def __init__(self, source_code_dir):
        self.source_code_dir = source_code_dir

    def analyze_files(self):
        """
        Analyzes Java source code files for common security vulnerabilities.
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
        Analyzes a single Java source code file for security vulnerabilities.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()

                # Example checks for common vulnerabilities
                self.check_hardcoded_credentials(file_path, content)
                self.check_insecure_network_calls(file_path, content)
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")

    def check_hardcoded_credentials(self, file_path, content):
        """
        Checks for hardcoded credentials in the Java source code.
        """
        pattern = re.compile(r'("password"|"passwd"|"apiKey"|"secret")\s*=\s*"[^"]+"')
        matches = pattern.findall(content)
        if matches:
            logger.warning(f"Found hardcoded credentials in {file_path}: {matches}")

    def check_insecure_network_calls(self, file_path, content):
        """
        Checks for insecure network calls (e.g., HTTP instead of HTTPS).
        """
        if "http://" in content:
            logger.warning(f"Found insecure HTTP call in {file_path}")

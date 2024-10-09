import os
import yara
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class YaraScanner:
    def __init__(self, rules_path, target_dir):
        self.rules_path = rules_path
        self.target_dir = target_dir
        self.rules = self.load_rules()

    def load_rules(self):
        """
        Loads YARA rules from the specified file.
        """
        if not os.path.exists(self.rules_path):
            logger.error(f"YARA rules file not found at {self.rules_path}")
            raise FileNotFoundError(f"YARA rules file not found at {self.rules_path}")

        try:
            rules = yara.compile(filepath=self.rules_path)
            logger.info(f"YARA rules loaded successfully from {self.rules_path}")
            return rules
        except yara.YaraSyntaxError as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            raise Exception(f"Failed to compile YARA rules: {e}")

    def scan_files(self):
        """
        Scans all files in the target directory using YARA rules.
        """
        if not os.path.exists(self.target_dir):
            logger.error(f"Target directory not found at {self.target_dir}")
            raise FileNotFoundError(f"Target directory not found at {self.target_dir}")

        for root, _, files in os.walk(self.target_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self.scan_file(file_path)

    def scan_file(self, file_path):
        """
        Scans a single file using YARA rules.
        """
        try:
            matches = self.rules.match(file_path)
            if matches:
                logger.warning(f"YARA match found in {file_path}: {[match.rule for match in matches]}")
        except Exception as e:
            logger.error(f"Failed to scan {file_path} with YARA: {e}")

import subprocess
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Decompiler:
    def __init__(self, apk_path, output_dir):
        self.apk_path = apk_path
        self.output_dir = output_dir

    def run_apktool(self):
        """
        Runs apktool to decompile the APK file.
        """
        try:
            subprocess.run(["apktool", "d", self.apk_path, "-o", self.output_dir, "--force"], check=True)
            logger.info(f"APK decompiled successfully to {self.output_dir}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to decompile APK with apktool: {e}")

    def run_jadx(self):
        """
        Runs jadx to decompile .dex files to Java source code.
        """
        try:
            subprocess.run(["jadx", "-d", self.output_dir, self.apk_path], check=True)
            logger.info(f"DEX files decompiled successfully to {self.output_dir}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to decompile DEX files with jadx: {e}")

    def decompile(self):
        """
        Runs both apktool and jadx to fully decompile the APK.
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        logger.info("Running apktool...")
        self.run_apktool()
        
        logger.info("Running jadx...")
        self.run_jadx()
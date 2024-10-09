import os
import xml.etree.ElementTree as ET
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ManifestScanner:
    def __init__(self, manifest_path):
        self.manifest_path = manifest_path

    def parse_manifest(self):
        """
        Parses the AndroidManifest.xml file and returns the XML tree.
        """
        if not os.path.exists(self.manifest_path):
            logger.error(f"Manifest file not found at {self.manifest_path}")
            raise FileNotFoundError(f"Manifest file not found at {self.manifest_path}")

        try:
            tree = ET.parse(self.manifest_path)
            return tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse AndroidManifest.xml: {e}")
            raise Exception(f"Failed to parse AndroidManifest.xml: {e}")

    def check_permissions(self, root):
        """
        Checks for dangerous permissions in the AndroidManifest.xml file.
        """
        dangerous_permissions = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS"
        ]

        found_permissions = []
        for permission in root.findall("uses-permission"):
            perm_name = permission.get("{http://schemas.android.com/apk/res/android}name")
            if perm_name in dangerous_permissions:
                found_permissions.append(perm_name)

        return found_permissions

    def check_exported_activities(self, root):
        """
        Checks if any activities are exported without proper security configurations.
        """
        exported_activities = []
        for activity in root.findall("application/activity"):
            exported = activity.get("{http://schemas.android.com/apk/res/android}exported")
            if exported == "true":
                activity_name = activity.get("{http://schemas.android.com/apk/res/android}name")
                exported_activities.append(activity_name)

        return exported_activities

    def scan(self):
        """
        Scans the AndroidManifest.xml file for security issues.
        """
        root = self.parse_manifest()

        # Check for dangerous permissions
        dangerous_permissions = self.check_permissions(root)
        if dangerous_permissions:
            logger.warning(f"Found dangerous permissions: {dangerous_permissions}")
        else:
            logger.info("No dangerous permissions found.")

        # Check for exported activities
        exported_activities = self.check_exported_activities(root)
        if exported_activities:
            logger.warning(f"Found exported activities without proper security: {exported_activities}")
        else:
            logger.info("No exported activities found.")
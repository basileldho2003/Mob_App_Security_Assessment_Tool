import os
import xml.etree.ElementTree as ET

def analyze_manifest(manifest_path):
    """
    Analyze the AndroidManifest.xml file for potential security issues.
    
    Parameters:
    - manifest_path: Path to the AndroidManifest.xml file.
    
    Returns:
    - A list of detected issues with their severity levels.
    """
    if not os.path.exists(manifest_path):
        print(f"Error: Manifest file not found at {manifest_path}")
        return []

    issues = []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        # Check for dangerous permissions
        dangerous_permissions = [
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA"
        ]

        for perm in root.findall("uses-permission"):
            permission_name = perm.get("{http://schemas.android.com/apk/res/android}name")
            if permission_name in dangerous_permissions:
                issues.append({
                    "issue_type": "Dangerous Permission",
                    "issue_detail": f"Permission {permission_name} found in manifest.",
                    "severity": "high"
                })

        # Check for exported activities/services/receivers
        exported_components = ["activity", "service", "receiver"]

        for component in exported_components:
            for elem in root.findall(component):
                exported = elem.get("{http://schemas.android.com/apk/res/android}exported")
                name = elem.get("{http://schemas.android.com/apk/res/android}name")
                if exported == "true":
                    issues.append({
                        "issue_type": f"Exported {component.capitalize()}",
                        "issue_detail": f"{component.capitalize()} {name} is exported, which may lead to security vulnerabilities.",
                        "severity": "medium"
                    })

        # Check for debuggable attribute
        application = root.find("application")
        if application is not None:
            debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                issues.append({
                    "issue_type": "Debuggable Application",
                    "issue_detail": "The application is set to be debuggable, which can expose it to potential attacks.",
                    "severity": "critical"
                })

    except ET.ParseError as e:
        print(f"Error parsing the AndroidManifest.xml file: {e}")
        return []

    return issues

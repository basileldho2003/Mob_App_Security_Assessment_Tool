import xml.etree.ElementTree as ET
import os

def analyze_manifest(manifest_path):
    """
    Analyze the AndroidManifest.xml file for potential security issues.
    """
    if not os.path.exists(manifest_path):
        print(f"Manifest file not found at {manifest_path}")
        return []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        issues = []

        # Check for uses-permission tags
        for permission in root.findall("uses-permission"):
            permission_name = permission.get("{http://schemas.android.com/apk/res/android}name")
            if permission_name in [
                "android.permission.INTERNET",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.READ_SMS",
            ]:
                issues.append({
                    'issue_type': 'Permission',
                    'issue_detail': f"Potentially dangerous permission requested: {permission_name}",
                    'severity': 'medium'
                })

        # Check if application allows backup
        application = root.find("application")
        if application is not None:
            allow_backup = application.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if allow_backup == "true":
                issues.append({
                    'issue_type': 'Configuration',
                    'issue_detail': "Application allows backup, which may lead to data leakage.",
                    'severity': 'high'
                })

            # Check for debuggable attribute
            debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                issues.append({
                    'issue_type': 'Configuration',
                    'issue_detail': "Application is set to be debuggable, which poses a security risk.",
                    'severity': 'high'
                })

        return issues
    except ET.ParseError as e:
        print(f"Error parsing manifest file: {e}")
        return []

# Testing code (for development purposes)
# if __name__ == "__main__":
#     manifest_path = "path/to/AndroidManifest.xml"
#     issues = analyze_manifest(manifest_path)
#     for issue in issues:
#         print(issue)

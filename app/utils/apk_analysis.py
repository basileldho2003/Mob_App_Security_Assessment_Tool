import os
import subprocess
from datetime import datetime
from xml.etree import ElementTree as ET
from app.utils.decompile import decompile_apk
from app.utils.yara_scan import yara_scan_apk
from app.utils.webview_vuln_check import check_webview_security

def analyze_apk(apk_path):
    """
    This function orchestrates the analysis of the APK by decompiling the APK,
    analyzing the AndroidManifest.xml, scanning for malware using YARA, and checking
    for WebView vulnerabilities.
    """

    # Step 1: Decompile APK
    output_dir = decompile_apk(apk_path)
    
    # Step 2: Analyze AndroidManifest.xml for permissions and security issues
    manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
    permissions_issues = analyze_manifest(manifest_path)

    # Step 3: YARA scan for malware
    yara_results = yara_scan_apk(output_dir)

    # Step 4: WebView vulnerability check
    java_files_path = os.path.join(output_dir, 'smali')
    webview_issues = check_webview_security(java_files_path)

    # Aggregate the results
    issues = permissions_issues + yara_results + webview_issues

    return {
        'apk_name': os.path.basename(apk_path),
        'issues': issues,
        'date': datetime.now()
    }

def analyze_manifest(manifest_path):
    """
    Analyzes the AndroidManifest.xml file for potential issues like dangerous
    permissions and insecure configurations.
    """
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = []
        for elem in root.iter('uses-permission'):
            permission = elem.get('{http://schemas.android.com/apk/res/android}name')
            permissions.append(permission)

        # Check for risky permissions
        return check_vulnerable_permissions(permissions)

    except Exception as e:
        return [f"Error analyzing manifest: {str(e)}"]

def check_vulnerable_permissions(permissions):
    """
    Checks the extracted permissions from AndroidManifest.xml for any permissions
    that are considered risky from a security perspective.
    """
    risky_permissions = [
        'android.permission.INTERNET',
        'android.permission.READ_SMS',
        'android.permission.WRITE_EXTERNAL_STORAGE',
        'android.permission.ACCESS_FINE_LOCATION',
    ]
    issues = []

    for permission in permissions:
        if permission in risky_permissions:
            issues.append(f"Risky permission detected: {permission}")

    if not issues:
        issues.append("No risky permissions found.")

    return issues

def yara_scan_apk(output_dir):
    """
    Performs a YARA scan on the decompiled APK files to check for known malware signatures.
    """
    yara_rules = 'rules/malware_rules.yar'  # Path to your YARA rules
    command = f"yara -r {yara_rules} {output_dir}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        return [f"YARA Scan Results:\n{result.stdout}"]
    else:
        return ["No malware detected via YARA."]

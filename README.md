# Mobile App Security Assessment Tool (MASAT)

> Note : This readme is under WIP. 👷🏻 <br>
> To be completed soon...

## analyze.py

```
import sys
import json
import traceback
from androguard.misc import AnalyzeAPK
import xml.etree.ElementTree as ET

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": "high",
    "android.permission.READ_SMS": "high",
    "android.permission.RECEIVE_SMS": "high",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "medium",
}

def analyze_permissions(apk):
    issues = []
    for perm in apk.get_permissions():
        severity = DANGEROUS_PERMISSIONS.get(perm, "info")
        issues.append({
            "type": "Permission",
            "detail": f"Requested permission: {perm}",
            "severity": severity
        })
    return issues

def analyze_intents(apk):
    issues = []
    for receiver in apk.get_declared_permissions():
        if "exported" in receiver and receiver["exported"]:
            issues.append({
                "type": "Intent Filter",
                "detail": f"Receiver {receiver['name']} is exported, which may be a security risk.",
                "severity": "high"
            })
    return issues

def analyze_api_calls(dx):
    issues = []
    for cls in dx.get_classes():
        for method in cls.get_methods():
            if method.is_external():
                continue
            for block in method.get_basic_blocks():
                for instruction in block.get_instructions():
                    output = instruction.get_output()
                    if "addJavascriptInterface" in output:
                        issues.append({
                            "type": "API Call",
                            "detail": f"Method {method.name} uses addJavascriptInterface, which may expose the app to security risks.",
                            "severity": "critical"
                        })
                    if "setJavaScriptEnabled" in output:
                        issues.append({
                            "type": "API Call",
                            "detail": f"Method {method.name} enables JavaScript, which may expose the app to XSS vulnerabilities.",
                            "severity": "high"
                        })
    return issues

def analyze_manifest(apk):
    """
    Analyze the AndroidManifest.xml file for security misconfigurations.
    """
    issues = []
    try:
        # Retrieve the manifest as XML
        manifest_xml = apk.get_android_manifest_axml().get_xml()
        manifest = ET.fromstring(manifest_xml)

        # Check for debuggable and allowBackup attributes
        application = manifest.find("application")
        if application is not None:
            if application.get("{http://schemas.android.com/apk/res/android}debuggable") == "true":
                issues.append({
                    "type": "Manifest",
                    "detail": "The application is debuggable, which is a security risk.",
                    "severity": "critical"
                })

            if application.get("{http://schemas.android.com/apk/res/android}allowBackup", "true") == "true":
                issues.append({
                    "type": "Manifest",
                    "detail": "The application allows backup, which may expose user data.",
                    "severity": "medium"
                })

    except Exception as e:
        print(f"Error analyzing manifest: {e}", file=sys.stderr)
        traceback.print_exc()
    return issues

def analyze_signing(apk):
    """
    Analyze the APK signing certificate for security weaknesses.
    """
    issues = []
    try:
        certificates = apk.get_certificates()
        if not certificates or len(certificates) == 0:
            issues.append({
                "type": "Certificate",
                "detail": "No signing certificate found. The APK may not be properly signed.",
                "severity": "critical"
            })
            return issues

        for cert in certificates:
            # Extract the public key from the certificate
            public_key = cert.public_key
            if public_key.bit_size < 2048:
                issues.append({
                    "type": "Certificate",
                    "detail": "The APK uses a signing certificate with a key size less than 2048 bits.",
                    "severity": "high"
                })
    except Exception as e:
        print(f"Error analyzing signing certificate: {e}", file=sys.stderr)
        traceback.print_exc()
        issues.append({
            "type": "Certificate",
            "detail": f"Error analyzing signing certificate: {str(e)}",
            "severity": "medium"
        })
    return issues

def analyze_apk(apk_path):
    issues = []
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        #print("APK analysis completed.")

        issues += analyze_permissions(a)
        issues += analyze_intents(a)
        issues += analyze_api_calls(dx)
        issues += analyze_manifest(a)
        issues += analyze_signing(a)

    except Exception as e:
        print(f"Error analyzing APK: {e}", file=sys.stderr)
        traceback.print_exc()
    return issues

if __name__ == "__main__":
    try:
        apk_path = sys.argv[1]  # Get APK path from command-line arguments
        #print(f"Received APK path: {apk_path}")
        issues = analyze_apk(apk_path)
        # print(issues)
        # print(type(issues))
        print(json.dumps(issues))  # Output results as JSON
        # print(type(json.dumps(issues)))
    except Exception as e:
        print(json.dumps({"error": f"Error analyzing APK: {str(e)}"}))
```
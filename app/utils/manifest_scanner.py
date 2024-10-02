import os
from pyaxmlparser import APK

def scan_android_manifest(decompiled_path):
    manifest_path = os.path.join(decompiled_path, 'AndroidManifest.xml')
    apk = APK(decompiled_path)
    issues = []

    if apk.is_signed():
        issues.append("App is signed.")
    if apk.is_permission_declared("android.permission.INTERNET"):
        issues.append("App has internet permission declared.")
    
    # Additional checks...
    return issues

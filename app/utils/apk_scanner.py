from app.utils.decompiler import decompile_apk
from app.utils.manifest_scanner import scan_android_manifest
from app.utils.code_scanner import scan_source_code
from app.utils.report_generator import generate_report

def scan_apk(apk_file_path):
    decompiled_dir = decompile_apk(apk_file_path)
    manifest_issues = scan_android_manifest(decompiled_dir)
    code_issues = scan_source_code(decompiled_dir)
    report = generate_report(manifest_issues, code_issues)
    return report

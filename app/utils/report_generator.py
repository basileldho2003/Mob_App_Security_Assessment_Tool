def generate_report(manifest_issues, code_issues):
    report = {
        'manifest_issues': manifest_issues,
        'code_issues': code_issues,
        'summary': f"Found {len(manifest_issues)} manifest issues and {len(code_issues)} code issues."
    }
    return report

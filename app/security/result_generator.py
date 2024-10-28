def generate_results(scan_id, manifest_issues, source_code_issues, payload_matches):
    """
    Generate consolidated results based on the scan analysis.

    Parameters:
    - scan_id: The ID of the scan being reported.
    - manifest_issues: A list of manifest issues detected.
    - source_code_issues: A list of source code issues detected.
    - payload_matches: A list of matched payloads detected during the scan.

    Returns:
    - A dictionary containing consolidated scan results.
    """
    # Initialize the results dictionary
    results = {
        "scan_id": scan_id,
        "manifest_issues": manifest_issues,
        "source_code_issues": source_code_issues,
        "payload_matches": payload_matches,
        "summary": {
            "total_manifest_issues": len(manifest_issues),
            "total_source_code_issues": len(source_code_issues),
            "total_payload_matches": len(payload_matches),
            "high_severity_issues": 0,
            "medium_severity_issues": 0,
            "low_severity_issues": 0,
            "critical_severity_issues": 0
        }
    }

    # Calculate severity counts for manifest issues
    for issue in manifest_issues:
        results["summary"][f"{issue['severity']}_severity_issues"] += 1

    # Calculate severity counts for source code issues
    for issue in source_code_issues:
        results["summary"][f"{issue['severity']}_severity_issues"] += 1

    # Calculate severity counts for payload matches (if they have severity levels)
    for match in payload_matches:
        if "severity" in match:
            results["summary"][f"{match['severity']}_severity_issues"] += 1

    return results

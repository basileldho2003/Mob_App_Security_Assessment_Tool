import os
import subprocess

def analyze_source_code(source_code_dir):
    """
    Analyze the Java source code files in the given directory for potential security issues using Semgrep.
    """
    if not os.path.exists(source_code_dir):
        print(f"Source code directory not found at {source_code_dir}")
        return []

    try:
        issues = []
        # Run Semgrep to analyze the Java source code
        semgrep_cmd = [
            "semgrep",
            "--config", "p/java/security-audit",
            source_code_dir,
            "--json"
        ]
        result = subprocess.run(semgrep_cmd, check=True, capture_output=True, text=True)

        # Parse the JSON output from Semgrep
        import json
        semgrep_results = json.loads(result.stdout)
        for finding in semgrep_results.get('results', []):
            issues.append({
                'file_path': finding['path'],
                'line_number': finding['start']['line'],
                'issue_type': finding['check_id'],
                'issue_detail': finding['extra']['message'],
                'severity': finding['extra'].get('severity', 'medium')
            })

        return issues
    except subprocess.CalledProcessError as e:
        print(f"Error during source code analysis: {e}")
        return []
    except Exception as e:
        print(f"Unexpected error: {e}")
        return []

# Testing code (for development purposes)
# if __name__ == "__main__":
#     source_code_dir = "path/to/source_code"
#     issues = analyze_source_code(source_code_dir)
#     for issue in issues:
#         print(issue)

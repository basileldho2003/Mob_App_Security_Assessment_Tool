import subprocess
import json
import os

from app.database.models import AndroguardAnalysis  # Import the new model
from app.database import db  # Import the database instance
from app.logger import logger

# Path to the Python interpreter in the Androguard environment
androguard_path = "" # Give path where analyze.py (provided in README.md) and 'androg' virtual environment is stored.
androguard_python = os.path.join(f"{androguard_path}androg", "bin", "python")  # Adjust for Windows: "androg\\Scripts\\python", ensure that virtual environment named 'androg' is created.
# Path to the Androguard analysis script
analyze_script = f"{androguard_path}analyze.py"

def analyze_apk_with_androguard(apk_path, scan_id):
    """
    Analyze an APK file using Androguard in a subprocess and save results.

    Parameters:
    - apk_path: Path to the APK file.
    - scan_id: ID of the scan to associate the results with.

    Returns:
    - A list of detected issues or an error message.
    """
    logger.info("Analysis begins...")

    try:
        # Run the Androguard script in a subprocess
        result = subprocess.run(
            [androguard_python, analyze_script, apk_path],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse the JSON output from the Androguard script
        if result.stdout.strip():
            issues = json.loads(result.stdout)

            # Save results to the database
            save_androguard_results(scan_id, issues)

            logger.info("Analysis completed and results saved.")
            return issues
        else:
            error_msg = "No output from analyze.py"
            save_androguard_results(scan_id, [{"type": "Error", "detail": error_msg, "severity": "critical"}])
            return [{"type": "Error", "detail": error_msg, "severity": "critical"}]

    except subprocess.CalledProcessError as e:
        error_msg = f"Subprocess error: {e.stderr}"
        save_androguard_results(scan_id, [{"type": "Error", "detail": error_msg, "severity": "critical"}])
        return [{"type": "Error", "detail": error_msg, "severity": "critical"}]
    except json.JSONDecodeError as e:
        error_msg = f"Invalid JSON output from analyze.py {e}"
        save_androguard_results(scan_id, [{"type": "Error", "detail": error_msg, "severity": "critical"}])
        return [{"type": "Error", "detail": error_msg, "severity": "critical"}]
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        save_androguard_results(scan_id, [{"type": "Error", "detail": error_msg, "severity": "critical"}])
        return [{"type": "Error", "detail": error_msg, "severity": "critical"}]


def save_androguard_results(scan_id, issues):
    """
    Save Androguard analysis results to the database.

    Parameters:
    - scan_id: ID of the scan to associate the results with.
    - issues: List of issues returned from analyze.py.
    """
    try:
        for issue in issues:
            new_issue = AndroguardAnalysis(
                scan_id=scan_id,
                issue_type=issue.get('type', 'Unknown'),
                issue_detail=issue.get('detail', 'No details provided'),
                severity=issue.get('severity', 'info')
            )
            db.session.add(new_issue)
        db.session.commit()
        logger.info(f"Saved {len(issues)} issues to the database.")
    except Exception as e:
        logger.error(f"Error saving Androguard results: {e}")
        db.session.rollback()

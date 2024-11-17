import subprocess
import json
import os

# Path to the Python interpreter in the Androguard environment
androguard_path = "/home/basilsvm/test_area/"
androguard_python = os.path.join(f"{androguard_path}androg", "bin", "python")  # Adjust for Windows: "androguard_env\\Scripts\\python"
# Path to the Androguard analysis script (saved as analyze_apk_script.py)
analyze_script = f"{androguard_path}analyze.py"  # Save your Androguard analysis logic in this file.

def analyze_apk_with_androguard(apk_path):
    """
    Analyze an APK file using Androguard in a subprocess.

    Parameters:
    - apk_path: Path to the APK file.

    Returns:
    - A list of detected issues or an error message.
    """
    print("Analysis begins...")

    try:
        # Run the Androguard script in a subprocess
        result = subprocess.run(
            [androguard_python, analyze_script, apk_path],
            capture_output=True,
            text=True,
            check=True,
        )
        # Parse the JSON output from the Androguard script
        print("Completed.")
        report=json.loads(result.stdout)
        print(report)
        return report

    except subprocess.CalledProcessError as e:
        return {"error": f"Subprocess failed: {e.stderr}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

# Example usage
# apk_file_path = f"{androguard_path}/Mini Browser_3.0_APKPure.apk"
# output = analyze_apk_with_androguard(apk_file_path)

# print("Detected Issues:")
# if "error" in output:
#     print(output["error"])
# else:
#     for issue in output:
#         print(issue)

# print("Completed")
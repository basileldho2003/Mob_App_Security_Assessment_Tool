import subprocess

def yara_scan_apk(output_dir):
    yara_rules = 'rules/malware_rules.yar'
    command = f"yara -r {yara_rules} {output_dir}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        return result.stdout
    else:
        return "No malware detected."

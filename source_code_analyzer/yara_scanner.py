import os
import yara

def scan_with_yara(source_code_dir, yara_rules_path):
    """
    Scan the given directory of source code files using YARA rules.
    """
    if not os.path.exists(source_code_dir):
        print(f"Source code directory not found at {source_code_dir}")
        return []

    if not os.path.exists(yara_rules_path):
        print(f"YARA rules file not found at {yara_rules_path}")
        return []

    try:
        # Compile YARA rules
        rules = yara.compile(filepath=yara_rules_path)
        issues = []

        # Walk through source code directory and scan each file
        for root, _, files in os.walk(source_code_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    matches = rules.match(file_path)
                    for match in matches:
                        issues.append({
                            'file_path': file_path,
                            'rule_name': match.rule,
                            'tags': match.tags,
                            'meta': match.meta
                        })
                except yara.Error as e:
                    print(f"Error scanning file {file_path}: {e}")

        return issues
    except yara.Error as e:
        print(f"Error compiling YARA rules: {e}")
        return []

# Testing code (for development purposes)
# if __name__ == "__main__":
#     source_code_dir = "path/to/source_code"
#     yara_rules_path = "path/to/yara_rules.yar"
#     issues = scan_with_yara(source_code_dir, yara_rules_path)
#     for issue in issues:
#         print(issue)
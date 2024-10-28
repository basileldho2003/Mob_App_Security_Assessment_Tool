import os
import yara

def load_yara_rules(rules_dir):
    """
    Load YARA rules from a specified directory.

    Parameters:
    - rules_dir: Path to the directory containing YARA rule files.

    Returns:
    - A compiled YARA rules object.
    """
    rules = {}
    
    # Traverse the rules directory to find all YARA files
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                rule_path = os.path.join(root, file)
                try:
                    rules[file] = yara.compile(filepath=rule_path)
                    print(f"Loaded YARA rule from {rule_path}")
                except yara.YaraSyntaxError as e:
                    print(f"Error compiling YARA rule at {rule_path}: {e}")

    return rules

def scan_with_yara(source_code_dir, rules):
    """
    Scan source code files using loaded YARA rules.

    Parameters:
    - source_code_dir: Path to the directory containing source code files.
    - rules: Compiled YARA rules object.

    Returns:
    - A list of payload matches with their details.
    """
    matches = []

    # Traverse the source code directory to find all files to scan
    for root, _, files in os.walk(source_code_dir):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    file_content = f.read()

                    # Apply each YARA rule to the file content
                    for rule_name, rule in rules.items():
                        rule_matches = rule.match(data=file_content)
                        for match in rule_matches:
                            matches.append({
                                "file_path": file_path,
                                "line_number": None,  # Line number tracking can be added if needed
                                "match_detail": f"Matched YARA rule '{match.rule}' in file '{file}'",
                                "severity": "high"  # Assign severity based on the nature of the rule
                            })

                except Exception as e:
                    print(f"Error reading or scanning file {file_path}: {e}")

    return matches

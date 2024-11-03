import os
import yara
from app.database.models import Payload
from app.database import db

def load_yara_rules(rules_dir):
    """
    Load YARA rules from a specified directory.

    Parameters:
    - rules_dir: Path to the directory containing YARA rule files.

    Returns:
    - A compiled YARA rules object.
    """
    rules = {}
    payload_map = {}  # New dictionary to store rule name to payload_id mapping

    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_path = os.path.join(root, file)
                try:
                    yara_rule = yara.compile(filepath=rule_path)
                    rules[file] = yara_rule

                    # Fetch or create a Payload entry for the rule and store the ID
                    payload = Payload.query.filter_by(payload_name=file).first()
                    if not payload:
                        payload = Payload(payload_name=file, pattern="", description="", severity="high")
                        db.session.add(payload)
                        db.session.commit()

                    payload_map[file] = payload.id  # Map rule name to payload ID
                except yara.YaraSyntaxError as e:
                    print(f"Error compiling YARA rule at {rule_path}: {e}")

    return rules, payload_map

def scan_with_yara(source_code_dir, rules, payload_map):
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
                            # Use payload_id from the mapping
                            payload_id = payload_map.get(rule_name)
                            matches.append({
                                "file_path": file_path,
                                "line_number": None,
                                "match_detail": f"Matched YARA rule '{match.rule}' in file '{file}'",
                                "severity": "high",  # Set severity or get it from payload if needed
                                "payload_id": payload_id  # Add payload_id for the match
                            })
                except Exception as e:
                    print(f"Error reading or scanning file {file_path}: {e}")

    return matches
import os
import javalang

def analyze_source_code(source_code_dir):
    """
    Analyze Java source code files for potential security issues.
    
    Parameters:
    - source_code_dir: Path to the directory containing Java source code files.
    
    Returns:
    - A list of detected issues with their severity levels.
    """
    issues = []

    # Traverse the source code directory to find all Java files
    for root, _, files in os.walk(source_code_dir):
        for file in files:
            if file.endswith(".java"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as java_file:
                    try:
                        source_code = java_file.read()
                        issues += analyze_java_file(file_path, source_code)
                    except Exception as e:
                        print(f"Error reading {file_path}: {e}")

    return issues


def analyze_java_file(file_path, source_code):
    """
    Perform basic analysis on a Java file using javalang-ext to detect potential issues.
    
    Parameters:
    - file_path: Path to the Java file.
    - source_code: Content of the Java file.
    
    Returns:
    - A list of detected issues in the given Java file.
    """
    issues = []

    try:
        # Parse the source code using javalang-ext
        tree = javalang.parse.parse(source_code)

        # Look for common insecure coding practices (simple examples)
        for _, method in tree.filter(javalang.tree.MethodDeclaration):
            # Example: Check for empty catch blocks
            if any(isinstance(stmt, javalang.tree.BlockStatement) and len(stmt.statements) == 0 for stmt in method.body):
                issues.append({
                    "file_path": file_path,
                    "line_number": method.position.line,
                    "issue_type": "Empty Catch Block",
                    "issue_detail": f"Method '{method.name}' contains an empty catch block, which may hide exceptions.",
                    "severity": "low"
                })

            # Example: Detect hard-coded credentials in the source code (simple regex)
            if "password" in method.name.lower() or "secret" in method.name.lower():
                issues.append({
                    "file_path": file_path,
                    "line_number": method.position.line,
                    "issue_type": "Hard-coded Credential",
                    "issue_detail": f"Method '{method.name}' may contain hard-coded credentials, which is a security risk.",
                    "severity": "high"
                })

    except javalang.parser.JavaSyntaxError as e:
        print(f"Syntax error in {file_path}: {e}")
    except Exception as e:
        print(f"Error analyzing {file_path}: {e}")

    return issues

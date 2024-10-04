import os

def check_webview_security(java_files_path):
    issues = []
    for root, dirs, files in os.walk(java_files_path):
        for file in files:
            if file.endswith('.smali'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    code = f.read()
                    if 'setJavaScriptEnabled(true)' in code:
                        issues.append(f"WebView JavaScript enabled in {file_path}")
                    if 'setWebViewClient' in code and 'shouldOverrideUrlLoading' not in code:
                        issues.append(f"WebView SSL validation missing in {file_path}")
    return issues

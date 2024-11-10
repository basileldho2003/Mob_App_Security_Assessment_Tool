rule Insecure_WebView_Configuration
{
    strings:
        $js_enabled = /setJavaScriptEnabled\s*\(\s*true\s*\)\s*;/  // JavaScript enabled
        $file_access = /setAllowFileAccess\s*\(\s*true\s*\)\s*;/   // File access enabled
        $untrusted_source = /setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)\s*;/  // Untrusted access
    condition:
        any of them
}

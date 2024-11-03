rule Hardcoded_Sensitive_Information
{
    strings:
        $apikey = /api[_\-]?key\s*=\s*["'][A-Za-z0-9]{32,}["']/
        $access_token = /access[_\-]?token\s*=\s*["'][A-Za-z0-9]{32,}["']/
        $password = /password\s*=\s*["'][A-Za-z0-9!@#\$%\^&*]{8,}["']/
    condition:
        any of them
}

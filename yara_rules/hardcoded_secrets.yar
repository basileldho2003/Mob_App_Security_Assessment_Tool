rule Hardcoded_Sensitive_Information
{
    strings:
        $apikey = /api[_\-]?key\s*=\s*["']\w{32,}["']/
        $access_token = /access[_\-]?token\s*=\s*["']\w{32,}["']/
        $password = /password\s*=\s*["'][A-Za-z0-9!@#\$%\^&*]{8,}["']/
    condition:
        any of them
}

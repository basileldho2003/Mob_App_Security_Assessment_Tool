rule Hardcoded_URLs_IPs
{
    strings:
        $http_url = /https?:\/\/[A-Za-z0-9\-\.]+\.[a-z]{2,6}(\/\S*)?/
        $ip_address = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
    condition:
        any of them
}

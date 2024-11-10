// rule Hardcoded_Urls_And_IPs
// {
//     strings:
//         $ip_address = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
//         $http_url = /http:\/\/[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/
//         $https_url = /https:\/\/[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}/
//     condition:
//         any of them
// }

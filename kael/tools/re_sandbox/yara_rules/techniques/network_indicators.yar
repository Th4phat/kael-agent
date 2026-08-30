rule Network_Activity {
    meta:
        description = "Detects network activity indicators"
        author = "Kael"
        severity = "medium"
    strings:
        $winsock = "ws2_32.dll" nocase
        $wininet = "wininet.dll" nocase
        $urlmon = "urlmon.dll" nocase
        $socket = "socket" nocase
        $connect = "connect" nocase
        $send = "send" nocase
        $recv = "recv" nocase
        $urldownloadtofile = "URLDownloadToFile" nocase
        $internetopen = "InternetOpen" nocase
        $internetconnect = "InternetConnect" nocase
        $httpopen = "HttpOpenRequest" nocase
        $httpsend = "HttpSendRequest" nocase
    condition:
        4 of them
}

rule C2_Beaconing_Patterns {
    meta:
        description = "Detects common C2 beaconing patterns"
        author = "Kael"
        severity = "high"
    strings:
        $sleep = "Sleep" nocase
        $gettickcount = "GetTickCount" nocase
        $http_user_agent = "User-Agent:" nocase
        $http_post = "POST" nocase
        $http_get = "GET" nocase
        $cookie = "Cookie:" nocase
        $authorization = "Authorization:" nocase
    condition:
        ($sleep or $gettickcount) and 2 of ($http*, $cookie, $authorization)
}

rule DNS_Tunneling {
    meta:
        description = "Detects DNS tunneling indicators"
        author = "Kael"
        severity = "high"
    strings:
        $dnsquery = "DnsQuery" nocase
        $gethostbyname = "gethostbyname" nocase
        $getaddrinfo = "getaddrinfo" nocase
        $base32_chars = /[A-Z2-7]{20,}/ nocase
        $base64_chars = /[A-Za-z0-9+\/]{20,}/
    condition:
        any of ($dns*, $get*) and any of ($base*)
}

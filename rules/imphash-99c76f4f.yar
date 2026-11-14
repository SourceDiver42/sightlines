rule Sightlines_imphash_99c76f4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-99c76f4f"
        date = "2026-11-03"
        campaign = "imphash-99c76f4f"
        family = ""
        hash = "1873a12d28da18fd915486d556508dfa805a15842855be1913ef256edcc0eebc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-99c76f4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TRACE: Strict-Transport-Security: max-age=31536000" ascii
        $s1 = "WARN: Strict-Transport-Security: max-age=31536000" ascii
        $s2 = "INFO: Access-Control-Allow-Methods: GET, POST, PUT, DELETE" ascii
        $s3 = "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8" ascii
        $s4 = "TRACE: Access-Control-Allow-Headers: Content-Type, Authorization" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s6 = "TRACE: Configuration loaded successfully" ascii
        $s7 = "WARN: SYSTEM\\\\CurrentControlSet\\\\Services" ascii
        $s8 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion" ascii
        $s9 = "DEBUG: Operation completed successfully" ascii
        $s10 = "TRACE: Loading configuration from registry" ascii
        $s11 = "DEBUG: X-Requested-With: XMLHttpRequest" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}

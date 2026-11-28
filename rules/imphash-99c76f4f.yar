rule Sightlines_imphash_99c76f4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-99c76f4f"
        date = "2026-11-25"
        campaign = "imphash-99c76f4f"
        family = ""
        hash = "1873a12d28da18fd915486d556508dfa805a15842855be1913ef256edcc0eebc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-99c76f4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TRACE: Strict-Transport-Security: max-age=31536000" ascii
        $s1 = "INFO: Access-Control-Allow-Methods: GET, POST, PUT, DELETE" ascii
        $s2 = "Accept-Language: en-US,en;q=0.9,zh-CN;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "TRACE: Configuration loaded successfully" ascii
        $s5 = "WARN: SYSTEM\\\\CurrentControlSet\\\\Services" ascii
        $s6 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion" ascii
        $s7 = "DEBUG: Operation completed successfully" ascii
        $s8 = "TRACE: Loading configuration from registry" ascii
        $s9 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s10 = "TRACE: X-Requested-With: XMLHttpRequest" ascii
        $s11 = "INFO: Operation completed successfully" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

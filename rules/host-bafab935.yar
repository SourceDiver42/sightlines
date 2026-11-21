rule Sightlines_host_bafab935_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-bafab935"
        date = "2026-10-23"
        campaign = "host-bafab935"
        family = "mirai"
        hash = "1128b9ab3653d22895991962a0aa5217ae6332b079671bf11c6995b4d15f18ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-bafab935.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "HOST: 255.255.255.255:1900" ascii
        $s5 = "MAN: \"ssdp:discover\"" ascii
        $s6 = "M-SEARCH * HTTP/1.1" ascii
        $s7 = "service:service-agent" ascii
        $s8 = "/tmp/condinetwork" ascii
        $s9 = "dWLuG@rPMFWAVQ" ascii
        $s10 = "/proc/%s/status" ascii
        $s11 = "/bin/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

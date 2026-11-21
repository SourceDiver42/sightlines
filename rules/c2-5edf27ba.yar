rule Sightlines_c2_5edf27ba_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-5edf27ba"
        date = "2026-11-19"
        campaign = "c2-5edf27ba"
        family = "mirai"
        hash = "027b645b8b20614d77d0648ed2c1765641fae5e6358ddacde2463c75cb2ce18f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-5edf27ba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "setsockopt(HDRINCL) failed" ascii
        $s5 = "Failed to create raw socket" ascii
        $s6 = "HOST: 255.255.255.255:1900" ascii
        $s7 = "MAN: \"ssdp:discover\"" ascii
        $s8 = "M-SEARCH * HTTP/1.1" ascii
        $s9 = "service:service-agent" ascii
        $s10 = "sendto failed" ascii
        $s11 = "FICMUHDKPJKCF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

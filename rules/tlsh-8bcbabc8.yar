rule Sightlines_tlsh_8bcbabc8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8bcbabc8"
        date = "2026-11-03"
        campaign = "tlsh-8bcbabc8"
        family = "mirai"
        hash = "3c200719ab2f52e785228ca28626df9d2b046c86defaa09d5a5e9697019c4b30"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8bcbabc8.json"
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
        $s8 = "objectClass0" ascii
        $s9 = "TeamSpeak" ascii
        $s10 = " default" ascii
        $s11 = "}CSx}e[x" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9e815b56_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9e815b56"
        date = "2026-11-02"
        campaign = "tlsh-9e815b56"
        family = "mirai"
        hash = "1fae1d5f7f5912d98ce0cd1d5d3482493a7401528b5c4084021c9e108151bc7f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9e815b56.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "qjwpefha[mw[pla[lmwpkv}[kb[qjmravwa" ascii
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s5 = "HOST: 239.255.255.250:1900" ascii
        $s6 = "HOST: 255.255.255.255:1900" ascii
        $s7 = "Connection: keep-alive" ascii
        $s8 = "MAN: \"ssdp:discover\"" ascii
        $s9 = " M-SEARCH * HTTP/1.1" ascii
        $s10 = "service:service-agent" ascii
        $s11 = "0.0 Safari/537.36" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

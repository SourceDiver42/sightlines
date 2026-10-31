rule Sightlines_tlsh_9b4b1d7a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b4b1d7a"
        date = "2026-10-29"
        campaign = "tlsh-9b4b1d7a"
        family = "mirai"
        hash = "402d61ce83de532591d6f8b0f8e897573ea4bdd3d417de993f4374f098df9cad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b4b1d7a.json"
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
        $s8 = "/lib/ld-uClibc.so.0" ascii
        $s9 = "__aeabi_uidivmod" ascii
        $s10 = "__errno_location" ascii
        $s11 = "FICMUHDKPJKCF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

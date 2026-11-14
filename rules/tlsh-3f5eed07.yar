rule Sightlines_tlsh_3f5eed07_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3f5eed07"
        date = "2026-11-11"
        campaign = "tlsh-3f5eed07"
        family = "mirai"
        hash = "441001f00c258a69d19accf005444e25f03a5923cda288d70d0e3b0779aa9de2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3f5eed07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "qjwpefha[mw[pla[lmwpkv}[kb[qjmravwa" ascii
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s5 = "HOST: 239.255.255.250:1900" ascii
        $s6 = "HOST: 255.255.255.255:1900" ascii
        $s7 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s8 = "MAN: \"ssdp:discover\"" ascii
        $s9 = "fkgfeplk`a*`arw*wqvb" ascii
        $s10 = "M-SEARCH * HTTP/1.1" ascii
        $s11 = "service:service-agent" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

rule Sightlines_tlsh_3f5eed07_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3f5eed07"
        date = "2026-11-15"
        campaign = "tlsh-3f5eed07"
        family = "mirai"
        hash = "0e19a043b5539dae0a6f8a4be74a08b0c4d267562c1bbb43ada1a7ca4ebe3d5a"
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
        $s7 = "Connection: keep-alive" ascii
        $s8 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s9 = "MAN: \"ssdp:discover\"" ascii
        $s10 = "fkgfeplk`a*`arw*wqvb" ascii
        $s11 = "M-SEARCH * HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

rule Sightlines_tlsh_c5fbbdca_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c5fbbdca"
        date = "2026-11-02"
        campaign = "tlsh-c5fbbdca"
        family = "mirai"
        hash = "96993b8671b76325b7b28fc59889e430a6212843a57cf03b9a3ba1725891892a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c5fbbdca.json"
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
        $s10 = "M-SEARCH * HTTP/1.1" ascii
        $s11 = "service:service-agent" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

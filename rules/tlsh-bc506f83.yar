rule Sightlines_tlsh_bc506f83_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc506f83"
        date = "2026-11-11"
        campaign = "tlsh-bc506f83"
        family = "mirai"
        hash = "149d00ce5205094687897a8e40867350869aaa34925f13d3a2283e48ef46225c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc506f83.json"
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
        $s9 = "/tmp/condinetwork" ascii
        $s10 = "dWLuG@rPMFWAVQ" ascii
        $s11 = "__aeabi_uidivmod" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

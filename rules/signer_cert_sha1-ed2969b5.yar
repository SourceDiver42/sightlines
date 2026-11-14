rule Sightlines_signer_cert_sha1_ed2969b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-ed2969b5"
        date = "2026-11-03"
        campaign = "signer_cert_sha1-ed2969b5"
        family = ""
        hash = "276f8d720e1a7c9c767dc1fe98528717c5508e36cdd4ae4cf3ddb08378f46317"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-ed2969b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "310107120000Z0r1" ascii
        $s1 = "310106000000Z0H1" ascii
        $s2 = "160107120000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 37079472 and 3 of them
}

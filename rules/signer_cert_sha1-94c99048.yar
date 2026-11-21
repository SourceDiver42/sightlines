rule Sightlines_signer_cert_sha1_94c99048_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-94c99048"
        date = "2026-11-17"
        campaign = "signer_cert_sha1-94c99048"
        family = ""
        hash = "e785a0c0dcf79385f0483c1eb2242e3937d0447f6b21dd158906e92757b46542"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-94c99048.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Private Organization1" ascii
        $s1 = "Alexander Roshal" wide
        $s2 = "Charlottenburg1" ascii
        $s3 = "win.rar GmbH0" ascii
        $s4 = "win.rar GmbH1" ascii
        $s5 = "260807235959Z0" ascii
        $s6 = "HRB 1098851" ascii
        $s7 = "230808000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8645024 and 8 of them
}

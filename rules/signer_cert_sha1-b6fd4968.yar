rule Sightlines_signer_cert_sha1_b6fd4968_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b6fd4968"
        date = "2026-11-20"
        campaign = "signer_cert_sha1-b6fd4968"
        family = ""
        hash = "236f7671aabdfa334f1effa1918f6ef131a8f4ad223e9790415c0528d684e157"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b6fd4968.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Private Organization1" ascii
        $s1 = "380114235959Z0i1" ascii
        $s2 = "271005235959Z0" ascii
        $s3 = "Acrobat DC1" ascii
        $s4 = "Adobe Inc.0" ascii
        $s5 = "Adobe Inc.1" ascii
        $s6 = "Adobe Acroba" wide
        $s7 = "San Jose1" ascii
        $s8 = "Delaware1" ascii
        $s9 = "251006000000Z" ascii
        $s10 = "nE}4bmFR" ascii
        $s11 = "250507000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7714736 and 12 of them
}

rule Sightlines_signer_cert_sha1_5a913d37_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-5a913d37"
        date = "2026-11-25"
        campaign = "signer_cert_sha1-5a913d37"
        family = ""
        hash = "3048df1cf8d476e998dde28ed6b67856b47ec5ae2b2c221fb1733f43c550c701"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-5a913d37.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201114Z0t1" ascii
        $s1 = "230012+5029230" ascii
        $s2 = "240912201114Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3244096 and 3 of them
}

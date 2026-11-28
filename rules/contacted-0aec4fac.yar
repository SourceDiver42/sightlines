rule Sightlines_contacted_0aec4fac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0aec4fac"
        date = "2026-11-24"
        campaign = "contacted-0aec4fac"
        family = ""
        hash = "0f5ce438306fb655a2eb4e50a4faf0bb9dde31e2215d3ffe3f9316671c5923d9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0aec4fac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "VGKNTA@CBBEC@DP/" ascii
        $s1 = "wsprintfA" ascii
        $s2 = "DDGF6n@$5" ascii
        $s3 = "_Mxq?QQ." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

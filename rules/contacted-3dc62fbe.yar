rule Sightlines_contacted_3dc62fbe_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-3dc62fbe"
        date = "2026-11-18"
        campaign = "contacted-3dc62fbe"
        family = "wardenstealer"
        hash = "2eef9e7d2a11d917c2d96600fcaa08533c8af152441b72baa1fe3db24fa80e6d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-3dc62fbe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RT_MANIFEST" wide
        $s1 = "D$ H3L$ H3" ascii
        $s2 = "x`I96t[I" ascii
        $s3 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1639424 and 4 of them
}

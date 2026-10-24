rule Sightlines_contacted_5175357c_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-5175357c"
        date = "2026-10-24"
        campaign = "contacted-5175357c"
        family = "prometei"
        hash = "0a16883a25d4d859ad2907f68981cd4c480d9bb27c2511de90e3d372162e5729"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-5175357c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "403 ForbH" ascii
        $s1 = "updatechH" ascii
        $s2 = "\"ZzY8<{j" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2577750 and 3 of them
}

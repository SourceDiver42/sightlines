rule Sightlines_contacted_c00f5d21_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-c00f5d21"
        date = "2026-11-18"
        campaign = "contacted-c00f5d21"
        family = ""
        hash = "123bbd4e5a5fd5352611f829198e0d0cb1e55b10f72e7b9200fd89edc9ca33ea"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-c00f5d21.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".+xmXKHHOX" ascii
        $s1 = "#U4v:zP3r" ascii
        $s2 = "R4qFKuU@#" ascii
        $s3 = "(Y~sT@Sz" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1348682 and 4 of them
}

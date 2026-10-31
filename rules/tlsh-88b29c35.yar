rule Sightlines_tlsh_88b29c35_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-88b29c35"
        date = "2026-10-29"
        campaign = "tlsh-88b29c35"
        family = "mirai"
        hash = "050583168146d4b174ba7c9005639d7af19cf95f54865e325019d297f077bdf9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-88b29c35.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "?/dev/null" ascii
        $s1 = " @N^NuNuNV" ascii
        $s2 = " @N^NuNV" ascii
        $s3 = " OHWHQHy" ascii
        $s4 = "HN^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}

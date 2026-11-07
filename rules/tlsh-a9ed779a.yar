rule Sightlines_tlsh_a9ed779a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a9ed779a"
        date = "2026-11-02"
        campaign = "tlsh-a9ed779a"
        family = "mirai"
        hash = "050583168146d4b174ba7c9005639d7af19cf95f54865e325019d297f077bdf9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a9ed779a.json"
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

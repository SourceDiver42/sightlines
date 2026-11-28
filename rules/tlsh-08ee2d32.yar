rule Sightlines_tlsh_08ee2d32_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-08ee2d32"
        date = "2026-11-09"
        campaign = "tlsh-08ee2d32"
        family = "mirai"
        hash = "3575a6a3ee1907c362c8f3d81e748372bbf82b984917a03d5e1029bfb672a007"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-08ee2d32.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dN^Nu8.8.8.8" ascii
        $s1 = " @N^NuNuNV" ascii
        $s2 = " JCfd Kp" ascii
        $s3 = "$_XONuNV" ascii
        $s4 = "(N^NuYO/" ascii
        $s5 = " @N^NuNV" ascii
        $s6 = " OHWHQHy" ascii
        $s7 = "HN^NuNuNV" ascii
        $s8 = "^lN^NuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_51f38c8f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51f38c8f"
        date = "2026-11-10"
        campaign = "tlsh-51f38c8f"
        family = ""
        hash = "7879df401dfbb36006c4589c08b957769bb1e06292474b6f432b1b30af4fb58c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51f38c8f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PathFindFileNameA" ascii
        $s1 = "wvsprintfW" ascii
        $s2 = "MAIN_ICON" wide
        $s3 = "StrRChrA" ascii
        $s4 = "StrStrIA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1590272 and 5 of them
}

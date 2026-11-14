rule Sightlines_imphash_2eda7f5a_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2eda7f5a"
        date = "2026-11-11"
        campaign = "imphash-2eda7f5a"
        family = "wardenstealer"
        hash = "02d92750b14f45431d21d394063bf94f8b6f5a471d15c4bef99a291e370396e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2eda7f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JLI_InitArgProcessing" ascii
        $s1 = "JLI_GetStdArgc" ascii
        $s2 = "JLI_GetStdArgs" ascii
        $s3 = "JLI_CmdToArgs" ascii
        $s4 = "JLI_MemAlloc" ascii
        $s5 = "JLI_MemFree" ascii
        $s6 = "JLI_Launch" ascii
        $s7 = "loader.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1088512 and 8 of them
}

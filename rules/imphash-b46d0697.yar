rule Sightlines_imphash_b46d0697_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b46d0697"
        date = "2026-11-21"
        campaign = "imphash-b46d0697"
        family = "wardenstealer"
        hash = "76847e43674b3b9c0f691d683b32c9442a2e19703db467db7e83b37ceb50c58e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b46d0697.json"
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
        uint16(0) == 0x5A4D and filesize < 1189888 and 8 of them
}

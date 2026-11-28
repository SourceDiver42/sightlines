rule Sightlines_imphash_acf9a896_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-acf9a896"
        date = "2026-11-26"
        campaign = "imphash-acf9a896"
        family = "wardenstealer"
        hash = "199bde7d21f9b5e3efc0ccd628d95f18b606b1df9a1ded483a38028adfd2e8e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-acf9a896.json"
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
        uint16(0) == 0x5A4D and filesize < 1434624 and 8 of them
}

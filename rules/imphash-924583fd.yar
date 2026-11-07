rule Sightlines_imphash_924583fd_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-924583fd"
        date = "2026-11-06"
        campaign = "imphash-924583fd"
        family = "wardenstealer"
        hash = "2eecf954b43401fbb644b9ca293150210ec284350ce1f20a0f57ff4a6b1f22e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-924583fd.json"
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
        uint16(0) == 0x5A4D and filesize < 1091584 and 8 of them
}

rule Sightlines_tlsh_81e18647_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-81e18647"
        date = "2026-11-13"
        campaign = "tlsh-81e18647"
        family = "wardenstealer"
        hash = "2653e398e71a94a8de4ff9425f7b00cff62ad41dc7f0b546ed4fb84aa1cf052b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-81e18647.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JLI_InitArgProcessing" ascii
        $s1 = "GetProcessHandleCount" ascii
        $s2 = "JLI_GetStdArgc" ascii
        $s3 = "JLI_GetStdArgs" ascii
        $s4 = "JLI_CmdToArgs" ascii
        $s5 = "JLI_MemAlloc" ascii
        $s6 = "JLI_MemFree" ascii
        $s7 = "JLI_Launch" ascii
        $s8 = "loader.dll" ascii
        $s9 = "D$ H3L$ H3" ascii
        $s10 = "L$HH1D$ " ascii
        $s11 = "LLD PDB." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1285120 and 12 of them
}

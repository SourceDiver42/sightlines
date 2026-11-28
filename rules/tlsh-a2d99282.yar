rule Sightlines_tlsh_a2d99282_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2d99282"
        date = "2026-11-11"
        campaign = "tlsh-a2d99282"
        family = "wardenstealer"
        hash = "8e21ff04e11b5942ed912f9801cf961019122f022c4aa99abfbd4bf0ade1c7fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2d99282.json"
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
        $s8 = "D$ H3L$ H3" ascii
        $s9 = "L$HH1D$ " ascii
        $s10 = "LLD PDB." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1264640 and 11 of them
}

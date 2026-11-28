rule Sightlines_tlsh_952f7c63_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-952f7c63"
        date = "2026-11-21"
        campaign = "tlsh-952f7c63"
        family = "wardenstealer"
        hash = "0d6834426f9847b301effed538a7823a508df58d117148c125fc82a6d59ffeb3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-952f7c63.json"
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
    condition:
        uint16(0) == 0x5A4D and filesize < 1467392 and 11 of them
}

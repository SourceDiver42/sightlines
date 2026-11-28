rule Sightlines_imphash_7be29123_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7be29123"
        date = "2026-11-27"
        campaign = "imphash-7be29123"
        family = "wardenstealer"
        hash = "371dfce9e332ef24012bc55e7496c993c3f1c4eebf11f9d81be9ca25077c4469"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7be29123.json"
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
        uint16(0) == 0x5A4D and filesize < 1340416 and 8 of them
}

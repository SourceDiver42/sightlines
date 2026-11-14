rule Sightlines_imphash_b3138877_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b3138877"
        date = "2026-11-13"
        campaign = "imphash-b3138877"
        family = "wardenstealer"
        hash = "0bde7430bfd3208baf0fc5bf62506caf8ff6f636dc9e20deadbbfd9643b61312"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b3138877.json"
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
        uint16(0) == 0x5A4D and filesize < 1112064 and 8 of them
}

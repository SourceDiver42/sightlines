rule Sightlines_imphash_924583fd_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-924583fd"
        date = "2026-11-20"
        campaign = "imphash-924583fd"
        family = "wardenstealer"
        hash = "05bc075d609943ef13d07e9fe5033ca89a031221e92fb6e6df305bbdff751c3b"
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
        uint16(0) == 0x5A4D and filesize < 1241088 and 8 of them
}

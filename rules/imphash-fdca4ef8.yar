rule Sightlines_imphash_fdca4ef8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fdca4ef8"
        date = "2026-11-11"
        campaign = "imphash-fdca4ef8"
        family = ""
        hash = "082d85d9b5b1596a049f2474f504369a181f6ffb9d6575948805eee4c9dc46c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fdca4ef8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "         <requestedExecutionLevel level='asInvoker' uiAccess='false'/>" ascii
        $s1 = "(\"{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" wide
        $s2 = "OneDrive sync updater" wide
        $s3 = "Sync Engine Components" wide
        $s4 = "IntervalBetweenEvents" wide
        $s5 = "Copyright (C) 2026" wide
        $s6 = "CommandLineTemplate" wide
        $s7 = "Device Sync Service" wide
        $s8 = "RunInteractively" wide
        $s9 = "\\InprocServer32" wide
        $s10 = "EventNamespace" wide
        $s11 = "MS_SYNC_CFG_V2" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3965954 and 12 of them
}

rule Sightlines_dotnet_typelib_guid_e7cd2a52_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-e7cd2a52"
        date = "2026-11-03"
        campaign = "dotnet_typelib_guid-e7cd2a52"
        family = "connectwise"
        hash = "4c281797c351fed77890634006a51bc3a6c60efa4c831fe21934353f304cdf61"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-e7cd2a52.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s2 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s3 = "SELECT * FROM Win32_GroupUser WHERE GroupComponent=\"Win32_Group.Domain='" wide
        $s4 = "SELECT * FROM Win32_UserAccount WHERE Name='" wide
        $s5 = "REPARSE_DATA_BUFFER_SymbolicLinkReparseBuffer" ascii
        $s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" wide
        $s7 = " deflate 1.2.7 Copyright 1995-2012 Jean-loup Gailly and Mark Adler " ascii
        $s8 = "(C) 1995-2012 Jean-loup Gailly & Mark Adler" wide
        $s9 = " inflate 1.2.7 Copyright 1995-2012 Mark Adler " ascii
        $s10 = "SELECT ProcessId, ParentProcessId FROM Win32_Process" wide
        $s11 = "<TemporarilySwitchProcessToWindowStation>b__0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3493888 and 9 of them
}

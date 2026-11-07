rule Sightlines_dotnet_typelib_guid_8a569b57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8a569b57"
        date = "2026-11-05"
        campaign = "dotnet_typelib_guid-8a569b57"
        family = ""
        hash = "0cceb3eb88916dfcf5e7cdef4eab8a74d42bc1bd38d842472dee97c9861bb8ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8a569b57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$00021401-0000-0000-C000-000000000046" ascii
        $s1 = "FormBorderStyle" ascii
        $s2 = "AutoScaleMode" ascii
        $s3 = "launcher.log" wide
        $s4 = "CreateParams" ascii
        $s5 = "CloseReason" ascii
        $s6 = "piShowCmd" ascii
        $s7 = "GetHotkey" ascii
        $s8 = "SetHotkey" ascii
        $s9 = "pwHotkey" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8163328 and 10 of them
}

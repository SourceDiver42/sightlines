rule Sightlines_dotnet_typelib_guid_f62824e3_quasarrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f62824e3"
        date = "2026-11-14"
        campaign = "dotnet_typelib_guid-f62824e3"
        family = "quasarrat"
        hash = "1ff5735495ffe8682929dfd00501140b778ff0c620e5f60e51b4c00a8d8437cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f62824e3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ExecuteInMemoryDotNet>k__BackingField" ascii
        $s1 = "PixelFormat differs from previous bitmap" wide
        $s2 = "<EightPointOneOrHigher>k__BackingField" ascii
        $s3 = "<IsLastRequestedFrame>k__BackingField" ascii
        $s4 = "<SetLastDirectorySeen>k__BackingField" ascii
        $s5 = "fileAccess must be either Read or Write." wide
        $s6 = "Bitmap dimensions differ from previous bitmap" wide
        $s7 = "82B9A2009DEB589583EC0C1532DD9E37EA0BF3825D6BB5D4A8371D393487FAF2" ascii
        $s8 = "Image quality must be between 0 and 100" wide
        $s9 = "<RecoveredAccounts>k__BackingField" ascii
        $s10 = "$c7c363ba-e5b6-4e18-9224-39bc8da73172" ascii
        $s11 = "<LastAccessTimeUtc>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3143680 and 12 of them
}

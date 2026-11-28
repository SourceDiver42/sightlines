rule Sightlines_dotnet_typelib_guid_251396fa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-251396fa"
        date = "2026-11-27"
        campaign = "dotnet_typelib_guid-251396fa"
        family = ""
        hash = "073eaa28846bed6b2702b3cc9ce3d4c63669293d16714b8e07f5da0a59aa31dd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-251396fa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{Enhanced memory standby list management with predictive purging, game-aware triggers, and kernel-le" ascii
        $s1 = "Enhanced memory standby list management with predictive purging, game-aware triggers, and kernel-lev" wide
        $s2 = ".Intelligent Standby List Cleaner (ISLC) Edited" ascii
        $s3 = "$D8A9F7C6-5E4B-4A3D-9F2C-8B1A7E6D5F4C" ascii
        $s4 = "vel memory orchestration" ascii
        $s5 = " Wagnardsoft 2026" ascii
        $s6 = "ISLC Edited.dll" ascii
        $s7 = "1.0.3.8-edited" ascii
        $s8 = "AutoScaleMode" ascii
        $s9 = "Copyright " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

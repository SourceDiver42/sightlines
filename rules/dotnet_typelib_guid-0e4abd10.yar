rule Sightlines_dotnet_typelib_guid_0e4abd10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-0e4abd10"
        date = "2026-11-07"
        campaign = "dotnet_typelib_guid-0e4abd10"
        family = ""
        hash = "3cf19156f24e80bc0d6686111748a6d38552c734666e9759b4dd14f4dd614ab1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-0e4abd10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QPhysics-enhanced puzzle box-pushing game with procedural generation and AI solver" ascii
        $s1 = "$A7E9D8C6-5F4B-4A3D-9F2C-8B1A7E6D5F4C" ascii
        $s2 = " PuzzleVault Studios 2025" ascii
        $s3 = "AdvancedSokoban.dll" ascii
        $s4 = "Advanced Sokoban" ascii
        $s5 = "AutoScaleMode" ascii
        $s6 = "7.4.8-deluxe" ascii
        $s7 = "%Copyright " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}

rule Sightlines_imphash_046d3873_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-046d3873"
        date = "2026-11-18"
        campaign = "imphash-046d3873"
        family = ""
        hash = "59134b754c6aca9449e2801e9e7ed55279c4f1ed58fe7a7a9f971c84e8a32a6c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-046d3873.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "python313.dll" ascii
        $s2 = "PyLong_AsInt" ascii
        $s3 = "PyModule_Add" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

rule Sightlines_imphash_4b2706d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4b2706d3"
        date = "2026-11-18"
        campaign = "imphash-4b2706d3"
        family = ""
        hash = "404353d7b867749fa2893033bd1ebf2e3f75322d4015725d697cfa5e80ec9d0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4b2706d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "python313.dll" ascii
        $s2 = "PyLong_AsInt" ascii
        $s3 = "PyModule_Add" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

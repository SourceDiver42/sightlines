rule Sightlines_imphash_5e81a654_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-5e81a654"
        date = "2026-11-18"
        campaign = "imphash-5e81a654"
        family = ""
        hash = "d080eabd015a3569813a220fd4ea74dff34ed2a8519a10473eb37e22b1118a06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-5e81a654.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "PyMapping_GetOptionalItemString" ascii
        $s2 = "python313.dll" ascii
        $s3 = "PyLong_AsInt" ascii
        $s4 = "PyModule_Add" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}

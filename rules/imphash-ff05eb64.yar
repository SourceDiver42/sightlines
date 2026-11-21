rule Sightlines_imphash_ff05eb64_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ff05eb64"
        date = "2026-11-18"
        campaign = "imphash-ff05eb64"
        family = ""
        hash = "76a33e2baa3880aa46290cc7d5810b3155c5e2f5a1cc7d3f7b751f6434144ada"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ff05eb64.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "python313.dll" ascii
        $s2 = "PyLong_AsInt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

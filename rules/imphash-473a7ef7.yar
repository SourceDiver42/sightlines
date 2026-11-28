rule Sightlines_imphash_473a7ef7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-473a7ef7"
        date = "2026-11-18"
        campaign = "imphash-473a7ef7"
        family = ""
        hash = "399d8c1a6607a97394a2ed735dcf3b489cf81048e81afe29bce7e0f53fb252c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-473a7ef7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "'sound' must be str, os.PathLike, or None, not %S" ascii
        $s2 = "Py_GetConstantBorrowed" ascii
        $s3 = "python313.dll" ascii
        $s4 = "|i:MessageBeep" ascii
        $s5 = "Oi:PlaySound" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

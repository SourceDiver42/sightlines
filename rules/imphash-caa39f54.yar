rule Sightlines_imphash_caa39f54_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-caa39f54"
        date = "2026-11-18"
        campaign = "imphash-caa39f54"
        family = ""
        hash = "1e349a13913370369059a4ae5951157112b5eba53ed4389c18ffc5e00af1a037"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-caa39f54.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s1 = "_PyParkingLot_Unpark" ascii
        $s2 = "_PyParkingLot_Park" ascii
        $s3 = "python313.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

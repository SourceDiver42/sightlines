rule Sightlines_imphash_dcb24ee2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dcb24ee2"
        date = "2026-11-05"
        campaign = "imphash-dcb24ee2"
        family = ""
        hash = "14dcccdd6a9850165da8d9740c79fb9939b61fd920b3ac2ffdc8a8a2b3d25324"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dcb24ee2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D$ H3L$ H3" ascii
        $s1 = "@8)u$H9j" ascii
        $s2 = "IDI_ICON1" wide
        $s3 = "f9)u$H9j" ascii
        $s4 = "u.H97uBA" ascii
        $s5 = "A82t@@8r" ascii
        $s6 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8676352 and 7 of them
}

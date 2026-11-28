rule Sightlines_imphash_528fbdda_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-528fbdda"
        date = "2026-11-22"
        campaign = "imphash-528fbdda"
        family = ""
        hash = "3fe103e29c7a6fb96619fddbdb80154459b0705a6276b1349108f77558f30645"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-528fbdda.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_environ" ascii
        $s1 = "amsi.dll" ascii
        $s2 = "D$D+D$HA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2515968 and 3 of them
}

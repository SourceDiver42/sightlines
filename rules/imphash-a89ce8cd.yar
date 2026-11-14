rule Sightlines_imphash_a89ce8cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a89ce8cd"
        date = "2026-11-12"
        campaign = "imphash-a89ce8cd"
        family = ""
        hash = "5a556f114dbd10030c30f454c0e793b1f2788617ce444d60914d5ee970e90544"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a89ce8cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6 6$6(6,6064686<6@6L6P6T6X6\\6`6d6h6l6p6t6x6|6" ascii
        $s1 = "687<7@7X7\\7`7d7h7l7p7t7x7|7" ascii
        $s2 = "0(0-03090?0F0K0P0`0e0j0z0" ascii
        $s3 = "1 10151:1J1O1T1d1i1n1~1" ascii
        $s4 = "3#3(383=3B3R3W3\\3l3q3v3" ascii
        $s5 = "2$24292>2N2S2X2h2m2r2" ascii
        $s6 = "0 0$001<1H1T1`1d1h1" ascii
        $s7 = "5 5(50585@5H5P5X5`5" ascii
        $s8 = "8*858:8?8Z8i8t8y8~8" ascii
        $s9 = "g2mcomm_winmain" ascii
        $s10 = "H2M2S2X2`2f2l2r2x2" ascii
        $s11 = "051D1K1Y1_1m1s1}1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6460416 and 12 of them
}

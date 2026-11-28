rule Sightlines_tlsh_d3935c95_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d3935c95"
        date = "2026-11-26"
        campaign = "tlsh-d3935c95"
        family = ""
        hash = "163baa843252ab2d03ae833b1400ab248e8d7c09082e3065a9e9cb680d5033ab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d3935c95.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "t1H;z(urH" ascii
        $s1 = "Cookie: H" ascii
        $s2 = "G(H;G v8H" ascii
        $s3 = "U(H;U vCH" ascii
        $s4 = "pqtuxy{}" ascii
        $s5 = "Accept: " ascii
        $s6 = "D$8Lct$4" ascii
        $s7 = "F$HcD$4A" ascii
        $s8 = "F2HcD$DA" ascii
        $s9 = "G$HcD$4A" ascii
        $s10 = "D$$HcD$TA" ascii
        $s11 = "G$HcD$PH" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

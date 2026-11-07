rule Sightlines_imphash_1c2c9a7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1c2c9a7a"
        date = "2026-11-05"
        campaign = "imphash-1c2c9a7a"
        family = ""
        hash = "265994409a3dbd511ff5bd6a6d24dea5b089d41f1dea8dcaeaabccd530ea09dd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1c2c9a7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide
        $s1 = "Elevation:Administrator!new:" wide
        $s2 = "%s_%s_tempchunk_%d" ascii
        $s3 = "D$XHcD$DH;D$Xs" ascii
        $s4 = "D$(HcD$HHcL$(H" ascii
        $s5 = "D$@H;D$Xt8H" ascii
        $s6 = "D$PH;D$Xs^H" ascii
        $s7 = "D$HH;D$htqH" ascii
        $s8 = "D$d;D$hr7H" ascii
        $s9 = "D$p;D$tt#H" ascii
        $s10 = "$H;D$0sPH" ascii
        $s11 = "T$0HcD$(H" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1527808 and 12 of them
}

rule Sightlines_contacted_3dc96904_rhadamanthys
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-3dc96904"
        date = "2026-11-11"
        campaign = "contacted-3dc96904"
        family = "rhadamanthys"
        hash = "4d621c82ff446589eb5506fe51c086d075f2762f0a3ec769f2417e95f716874c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-3dc96904.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "w{Z8ygZ(:7V" ascii
        $s1 = "4(tT]8Q`MS" ascii
        $s2 = "5-J{z1|*lE" ascii
        $s3 = ">BWm}7\"Sv$" ascii
        $s4 = "?QJ-tGSa|&" ascii
        $s5 = ";wnzjv~L}" ascii
        $s6 = "P~O^v?CQA" ascii
        $s7 = "qh`6SmtOL" ascii
        $s8 = "uU+yS&G5)" ascii
        $s9 = "v\"D3m|)cQ" ascii
        $s10 = "&J!,zsXp" ascii
        $s11 = "'X8KS\\6}" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6652928 and 12 of them
}

rule Sightlines_tlsh_4aa1b8f2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4aa1b8f2"
        date = "2026-10-15"
        campaign = "tlsh-4aa1b8f2"
        family = ""
        hash = "65a8977a7722df64116a12adf062ec1bcd0cefabe8bccc94307d9aa1b8145134"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4aa1b8f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "SHf7,-fz=8p5$YD" ascii
        $s3 = " nFc1OJT5pNvIn" ascii
        $s4 = "widozagecidaboza" ascii
        $s5 = "tPf9*tKf9l$0tDH" ascii
        $s6 = "1WkMrCmbc$w.{" ascii
        $s7 = "aIt*J;~HQK&W0" ascii
        $s8 = "HR8~H:x&,@K7w" ascii
        $s9 = "3=;Y3u#qK=g1W" ascii
        $s10 = "2iVf&rF{QIy7" ascii
        $s11 = "WE7y#uO9'M_1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9918464 and 12 of them
}

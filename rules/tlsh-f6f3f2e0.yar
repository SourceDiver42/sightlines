rule Sightlines_tlsh_f6f3f2e0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f6f3f2e0"
        date = "2026-11-03"
        campaign = "tlsh-f6f3f2e0"
        family = "mirai"
        hash = "3dc3659a6ca0b5e60292778a27e905856debd2c9285f436f9356b0c055a88905"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f6f3f2e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s1 = "cannot create TLS data structures: ABORT" ascii
        $s2 = "cannot allocate memory in static TLS block" ascii
        $s3 = "Invalid multibyte format string." ascii
        $s4 = "FATAL: exception not rethrown" ascii
        $s5 = "EUQ\\J),HMP.5;VY9=@D'GKN" wide
        $s6 = "npxXoudifFeEgGaACSnmcs[" ascii
        $s7 = "g|GGGGGGGGGGGGGGSYYY*GGGGGGGGGGG_WLsxGGGGGGGGGGGGG_YYWGGGGGGGGGGGGXIZ+_IE_GIUIZYDF" ascii
        $s8 = "fffffaffff&fDDDDDDDdDDD$\"\"\"\"\"\"\"b" ascii
        $s9 = "Unknown error Success" ascii
        $s10 = "$+3=FMVZ^bfjnrvz~" wide
        $s11 = "e1:q9:get_peers1:t2:" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

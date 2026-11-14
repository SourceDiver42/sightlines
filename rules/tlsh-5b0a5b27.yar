rule Sightlines_tlsh_5b0a5b27_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b0a5b27"
        date = "2026-11-03"
        campaign = "tlsh-5b0a5b27"
        family = "mirai"
        hash = "7cdf57c7e6017583df56cb081f8e488f6fe45782e059a97515e049487c0e6f4f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b0a5b27.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s1 = "cannot create TLS data structures: ABORT" ascii
        $s2 = "cannot allocate memory in static TLS block" ascii
        $s3 = "Invalid multibyte format string." ascii
        $s4 = "Ba,2a-2a.2a/2a02a12a22a32a42a5Ba62a72a82a92a:2a;2a<2a=2a>2a?2a@2aA2aB2aC2aD2aE2aF2aG2aH2aIB" ascii
        $s5 = "FATAL: exception not rethrown" ascii
        $s6 = "EUQ\\J),HMP.5;VY9=@D'GKN" wide
        $s7 = "npxXoudifFeEgGaACSnmcs[" ascii
        $s8 = "g|GGGGGGGGGGGGGGSYYY*GGGGGGGGGGG_WLsxGGGGGGGGGGGGG_YYWGGGGGGGGGGGGXIZ+_IE_GIUIZYDF" ascii
        $s9 = "USE_ABSOLUTE_LITERALS=0" ascii
        $s10 = "fffffaffff&fDDDDDDDdDDD$\"\"\"\"\"\"\"b" ascii
        $s11 = "Unknown error Success" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

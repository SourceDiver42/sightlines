rule Sightlines_rich_header_hash_ccfe3e4a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-ccfe3e4a"
        date = "2026-11-11"
        campaign = "rich_header_hash-ccfe3e4a"
        family = ""
        hash = "2b729876626ee9b2a3cc84cfc081c0c71cf2b688a78429f0c01aa3e190df2d0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-ccfe3e4a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "456789:;<=>?@ABCDEFGHIK" ascii
        $s1 = " P4nGM:-0\\58FMRi" ascii
        $s2 = "<@DddddLPTXdddd\\`hl@" ascii
        $s3 = ",0HFFFFL48<6FFF@DP," ascii
        $s4 = "E(8A:0*HtS'dTf=" ascii
        $s5 = "TSRi@~dh4qJ!V%)" ascii
        $s6 = "ph2h(ypA/D%D&jH@" ascii
        $s7 = "(5r%S%X,W2Ur6h0" ascii
        $s8 = "048<)222@DHb[HI" ascii
        $s9 = "$W%K\\HM!CD?LLN" ascii
        $s10 = "* 4WIe\" *4UeB8[" ascii
        $s11 = "i@@DDD4MkFHH$LLL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29025280 and 12 of them
}

rule Sightlines_tlsh_b2ff9549_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b2ff9549"
        date = "2026-11-10"
        campaign = "tlsh-b2ff9549"
        family = "wardenstealer"
        hash = "0b2819788851c15b892ea140a7fdc6e791f02e29cd0e02461b871e1fe061aa13"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b2ff9549.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RT_MANIFEST" wide
        $s1 = "D$ H3L$ H3" ascii
        $s2 = "x`I96t[I" ascii
        $s3 = "L$HH1D$ " ascii
        $s4 = "T$HH;T$8" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1574912 and 5 of them
}

rule Sightlines_tlsh_3e6084a4_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3e6084a4"
        date = "2026-11-24"
        campaign = "tlsh-3e6084a4"
        family = "wardenstealer"
        hash = "98a5e3003d095984d8d0e449c545677f890788be70e533404a6b89514b5f9c92"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3e6084a4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RT_MANIFEST" wide
        $s1 = "D$ H3L$ H3" ascii
        $s2 = "x`I96t[I" ascii
        $s3 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1690624 and 4 of them
}

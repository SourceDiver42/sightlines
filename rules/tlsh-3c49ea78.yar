rule Sightlines_tlsh_3c49ea78_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c49ea78"
        date = "2026-11-19"
        campaign = "tlsh-3c49ea78"
        family = "wardenstealer"
        hash = "1f60365163900a9725ef49bb84e735ead84355c33d2a489940c0f10ed644901e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c49ea78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RT_MANIFEST" wide
        $s1 = "D$ H3L$ H3" ascii
        $s2 = "x`I96t[I" ascii
        $s3 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1489920 and 4 of them
}

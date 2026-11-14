rule Sightlines_tlsh_1dc1672e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1dc1672e"
        date = "2026-11-08"
        campaign = "tlsh-1dc1672e"
        family = ""
        hash = "36311080c712f7d3f70bdae08038ac4fcfb38f47fbb2b56df222e4b775f637c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1dc1672e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "o$_jZkbkU" ascii
        $s1 = "Y 9X s&9A" ascii
        $s2 = "$dw'Cy0b" ascii
        $s3 = "T$ 9J0t " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1846272 and 4 of them
}

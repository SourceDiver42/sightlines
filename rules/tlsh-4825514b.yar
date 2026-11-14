rule Sightlines_tlsh_4825514b_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4825514b"
        date = "2026-11-06"
        campaign = "tlsh-4825514b"
        family = "agenttesla"
        hash = "1d8d3c271c5d5787d59477158afa7f6cc0c9f45dc777f8ff912da5f78c8552e1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4825514b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\".spli" ascii
        $s1 = "2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\";func" ascii
        $s2 = "u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631Obje\\u2631\\u2631\\" ascii
        $s3 = "1\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631ng.\\u2631" ascii
        $s4 = "2631\\u2631\\u2631\\u2631eSy\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2" ascii
        $s5 = "31\\u2631\\u2631\\u2631\\u2631\\u2631LDO\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u263" ascii
        $s6 = "31\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631ste\\u263" ascii
        $s7 = "31\\u2631\\u2631\\u2631\\u2631\\u2631g.F\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u263" ascii
        $s8 = "631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631bje\\u26" ascii
        $s9 = "631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631ft.\\u2631\\u26" ascii
        $s10 = "631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631g.F\\u2631\\u2631\\u26" ascii
        $s11 = "1\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631\\u2631ip\\u2631\\" ascii
    condition:
        filesize < 6996968 and 12 of them
}

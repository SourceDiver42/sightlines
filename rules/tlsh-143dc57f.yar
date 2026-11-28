rule Sightlines_tlsh_143dc57f_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-143dc57f"
        date = "2026-11-21"
        campaign = "tlsh-143dc57f"
        family = "remcos"
        hash = "1d49bb42a6c22a0e191c12d3a2535e37d88bf93e125a34710fb27a1b201db21d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-143dc57f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\".spli" ascii
        $s1 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\";var " ascii
        $s2 = "u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Obje\\u2642\\u2642\\" ascii
        $s3 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642bje\\u26" ascii
        $s4 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u26" ascii
        $s5 = "u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u" ascii
        $s6 = "42\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ste\\u264" ascii
        $s7 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642LDO\\u2642\\u2642\\u2642\\u2" ascii
        $s8 = "2642\\u2642\\u2642\\u2642eSy\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2" ascii
        $s9 = "2\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ng.\\u2642" ascii
        $s10 = "2\\u2642\\u2642\\u2642\\u2642\\u2642ft.\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642" ascii
        $s11 = "\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Fi\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u" ascii
    condition:
        filesize < 9032532 and 12 of them
}

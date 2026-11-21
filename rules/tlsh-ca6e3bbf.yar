rule Sightlines_tlsh_ca6e3bbf_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ca6e3bbf"
        date = "2026-11-12"
        campaign = "tlsh-ca6e3bbf"
        family = "agenttesla"
        hash = "1800d0b050584d05cd3f9d0bc2b4414633881254edf4cd2211e5007187df88af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ca6e3bbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635Obje\\u2635\\" ascii
        $s1 = "2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ng.\\u2" ascii
        $s2 = "2635\\u2635\\u2635\\u2635\\u2635eSy\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2" ascii
        $s3 = "635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635g.F\\u2635\\u26" ascii
        $s4 = "\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635bje\\" ascii
        $s5 = "\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ft.\\u2635\\u2635\\u2635\\u2635\\u2635\\" ascii
        $s6 = "u2635\\u2635LDO\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u" ascii
        $s7 = "u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ste\\u" ascii
        $s8 = "2635\\u2635\\u2635\\u2635\\u2635Sc\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u26" ascii
        $s9 = "2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ip\\u26" ascii
        $s10 = "2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635mO\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u26" ascii
        $s11 = "2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ri\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u26" ascii
    condition:
        filesize < 6476672 and 12 of them
}

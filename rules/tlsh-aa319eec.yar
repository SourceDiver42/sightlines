rule Sightlines_tlsh_aa319eec_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aa319eec"
        date = "2026-11-11"
        campaign = "tlsh-aa319eec"
        family = "agenttesla"
        hash = "368ae45a54fbe688349cb6ce2e43cb5c8ce3628ca5b0306b3e2daffb5e0ea76f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aa319eec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635Obje\\u2635\\" ascii
        $s1 = "2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ng.\\u2" ascii
        $s2 = "2635\\u2635\\u2635\\u2635\\u2635eSy\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2" ascii
        $s3 = "\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635bje\\" ascii
        $s4 = "\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ft.\\u2635\\u2635\\u2635\\u2635\\u2635\\" ascii
        $s5 = "u2635\\u2635LDO\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u" ascii
        $s6 = "u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ste\\u" ascii
        $s7 = "635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635g.F\\u2635\\u26" ascii
        $s8 = "35\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635cr\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s9 = "35\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ti\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s10 = "35\\u2635il\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s11 = "35ro\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
    condition:
        filesize < 6476688 and 12 of them
}

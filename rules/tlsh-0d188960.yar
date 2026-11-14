rule Sightlines_tlsh_0d188960_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d188960"
        date = "2026-11-11"
        campaign = "tlsh-0d188960"
        family = "agenttesla"
        hash = "504dbeee84ba5849fada385cb22dd64621d67965551b81717a771a6e44cbf836"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d188960.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Eri\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u26" ascii
        $s1 = "2E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Et.\\u262E\\u262E\\u262E" ascii
        $s2 = "E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Eb\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u" ascii
        $s3 = "\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262EM\\u2" ascii
        $s4 = "2E\\u262E\\u262E\\u262E\\u262E\\u262ES\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\" ascii
        $s5 = "2E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262ED\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\" ascii
        $s6 = "2E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u" ascii
        $s7 = "62E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\" ascii
        $s8 = "E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u2" ascii
        $s9 = "\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u26" ascii
        $s10 = "262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E" ascii
        $s11 = "u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262" ascii
    condition:
        filesize < 6282822 and 12 of them
}

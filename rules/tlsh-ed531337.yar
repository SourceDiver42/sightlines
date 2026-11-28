rule Sightlines_tlsh_ed531337_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed531337"
        date = "2026-11-21"
        campaign = "tlsh-ed531337"
        family = ""
        hash = "0c2baf3bf5031e111f3ada9acf2612e961a5f9325a56762614c65493b2ee5813"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed531337.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\".spli" ascii
        $s1 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\";var " ascii
        $s2 = "u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Obje\\u2642\\u2642\\" ascii
        $s3 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642bje\\u26" ascii
        $s4 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u26" ascii
        $s5 = "42\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ste\\u264" ascii
        $s6 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642LDO\\u2642\\u2642\\u2642\\u2" ascii
        $s7 = "2642\\u2642\\u2642\\u2642eSy\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2" ascii
        $s8 = "2\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ng.\\u2642" ascii
        $s9 = "2\\u2642\\u2642\\u2642\\u2642\\u2642ft.\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642" ascii
        $s10 = "\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Fi\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u" ascii
        $s11 = "\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Sy\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u" ascii
    condition:
        filesize < 5875800 and 12 of them
}

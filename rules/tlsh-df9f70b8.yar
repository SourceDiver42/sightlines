rule Sightlines_tlsh_df9f70b8_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-df9f70b8"
        date = "2026-11-20"
        campaign = "tlsh-df9f70b8"
        family = "remcos"
        hash = "4dff1312677058021a18ef3feb92f6573223d779b31577a79e64fd294305c9a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-df9f70b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\".spli" ascii
        $s1 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\";var " ascii
        $s2 = "u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Obje\\u2642\\u2642\\" ascii
        $s3 = "42\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ste\\u264" ascii
        $s4 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642bje\\u26" ascii
        $s5 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u26" ascii
        $s6 = "u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u" ascii
        $s7 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642LDO\\u2642\\u2642\\u2642\\u2" ascii
        $s8 = "2642\\u2642\\u2642\\u2642eSy\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2" ascii
        $s9 = "2\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ng.\\u2642" ascii
        $s10 = "2\\u2642\\u2642\\u2642\\u2642\\u2642ft.\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642" ascii
        $s11 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642em\\u2642\\u2642\\u2642\\u2642\\u2642\\u264" ascii
    condition:
        filesize < 9032516 and 12 of them
}

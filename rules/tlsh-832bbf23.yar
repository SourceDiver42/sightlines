rule Sightlines_tlsh_832bbf23_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-832bbf23"
        date = "2026-11-24"
        campaign = "tlsh-832bbf23"
        family = "agenttesla"
        hash = "0abaa82905f866bb2b818eeec2ff1b8b789a9f7d502962e07ea279635aa65dab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-832bbf23.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\".spli" ascii
        $s1 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\";var " ascii
        $s2 = "u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642Obje\\u2642\\u2642\\" ascii
        $s3 = "42\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ste\\u264" ascii
        $s4 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642bje\\u26" ascii
        $s5 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u26" ascii
        $s6 = "2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642LDO\\u2642\\u2642\\u2642\\u2" ascii
        $s7 = "2642\\u2642\\u2642\\u2642eSy\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2" ascii
        $s8 = "2\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642ng.\\u2642" ascii
        $s9 = "2\\u2642\\u2642\\u2642\\u2642\\u2642ft.\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642" ascii
        $s10 = "2\\u2642\\u2642\\u2642\\u2642\\u2642g.F\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642" ascii
        $s11 = "642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642\\u2642em\\u2642\\u2642\\u2642\\u2642\\u2642\\u264" ascii
    condition:
        filesize < 7392260 and 11 of them
}

rule Sightlines_tlsh_f9f8f09f_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f9f8f09f"
        date = "2026-11-19"
        campaign = "tlsh-f9f8f09f"
        family = "agenttesla"
        hash = "07ca4fa61082d6d5aee61424e027e4b3ecd3cb2c4800fe30f70472ac11fff5d3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f9f8f09f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "','Position','Write','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s1 = "','1650909PAaKZv','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2" ascii
        $s2 = "','ERROR:\\x20','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s3 = "2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640','Close','\\u2640\\u2640\\u2640\\u2640\\" ascii
        $s4 = "','\\u2640\\u2640\\u2640','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s5 = "640\\u2640\\u2640\\u2640Obje\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2" ascii
        $s6 = "0\\u2640\\u2640\\u2640g.F\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s7 = "2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640bje\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2" ascii
        $s8 = "40\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ng.\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u264" ascii
        $s9 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640g.F\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s10 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ste\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s11 = "\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ft.\\u2640\\" ascii
    condition:
        filesize < 7663970 and 12 of them
}

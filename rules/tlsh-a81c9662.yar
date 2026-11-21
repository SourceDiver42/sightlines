rule Sightlines_tlsh_a81c9662_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a81c9662"
        date = "2026-11-20"
        campaign = "tlsh-a81c9662"
        family = "remcos"
        hash = "a39ead617b1c8967434ae3aaa07018508a1d741ba5331a819dd7dd0b029183d2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a81c9662.json"
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
        $s8 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640g.F\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s9 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ste\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s10 = "\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ft.\\u2640\\" ascii
        $s11 = "\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640eSy\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\" ascii
    condition:
        filesize < 10339902 and 12 of them
}

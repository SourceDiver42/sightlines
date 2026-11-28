rule Sightlines_tlsh_49dfdbb2_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-49dfdbb2"
        date = "2026-11-18"
        campaign = "tlsh-49dfdbb2"
        family = "agenttesla"
        hash = "1bd3ad143864bf777e01665da6ba140d37ab43029bf3f5b53abfbe4beb1312c9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-49dfdbb2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "','Position','Write','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s1 = "','1650909PAaKZv','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2" ascii
        $s2 = "','ERROR:\\x20','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s3 = "2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640','Close','\\u2640\\u2640\\u2640\\u2640\\" ascii
        $s4 = "','\\u2640\\u2640\\u2640','\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s5 = "640\\u2640\\u2640\\u2640Obje\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2" ascii
        $s6 = "0\\u2640\\u2640\\u2640g.F\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640" ascii
        $s7 = "40\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ng.\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u264" ascii
        $s8 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640g.F\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s9 = "640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ste\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u26" ascii
        $s10 = "\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640ft.\\u2640\\" ascii
        $s11 = "\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640eSy\\u2640\\u2640\\u2640\\u2640\\u2640\\u2640\\" ascii
    condition:
        filesize < 7652994 and 12 of them
}

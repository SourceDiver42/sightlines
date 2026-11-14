rule Sightlines_tlsh_97c9e4c6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97c9e4c6"
        date = "2026-11-07"
        campaign = "tlsh-97c9e4c6"
        family = ""
        hash = "3f76eacfa6007be49589cec316f94c09751024d79ebefc3c8ca68d991a255bb5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97c9e4c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "// @COMPANY: MADE WITH LOVE ON  COUNTRY" ascii
        $s1 = "u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\".spl" ascii
        $s2 = "\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262EObje\\u262E\\u262E" ascii
        $s3 = "u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\";fun" ascii
        $s4 = "62E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Este\\u26" ascii
        $s5 = "u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262ELDO\\u262E\\u262E\\u262E\\u" ascii
        $s6 = "u262E\\u262E\\u262E\\u262EeSy\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u" ascii
        $s7 = "262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Ebje\\u2" ascii
        $s8 = "262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Eg.F\\u262E\\u262E\\u2" ascii
        $s9 = "2E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262Eng.\\u262" ascii
        $s10 = "2E\\u262E\\u262E\\u262E\\u262E\\u262Eft.\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262" ascii
        $s11 = "E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262EFi\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\u262E\\" ascii
    condition:
        filesize < 5201474 and 12 of them
}

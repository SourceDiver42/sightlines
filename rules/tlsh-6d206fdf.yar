rule Sightlines_tlsh_6d206fdf_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6d206fdf"
        date = "2026-11-13"
        campaign = "tlsh-6d206fdf"
        family = "xworm"
        hash = "59cc0cadec851415fc55523c90e4f73815d0fa566f005f64702b28cb89db6f55"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6d206fdf.json"
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
        $s8 = "35\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635cr\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s9 = "35\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635ti\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s10 = "35\\u2635il\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
        $s11 = "35ro\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635\\u2635" ascii
    condition:
        filesize < 4812804 and 12 of them
}

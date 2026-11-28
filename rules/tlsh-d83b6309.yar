rule Sightlines_tlsh_d83b6309_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d83b6309"
        date = "2026-11-20"
        campaign = "tlsh-d83b6309"
        family = "remcos"
        hash = "0cea411347dbcb05f1a22bf959c8640ca0531d451146ed547acb9fd12ff35b23"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d83b6309.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "''),0x1*-0x9b+0x10b*-0x19+-0x356*-0x8);" ascii
        $s1 = "5961','CreateObject','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E" ascii
        $s2 = "RLA(0xcc2+-0x47e*-0x7+-0x9d*0x46);" ascii
        $s3 = "'](''),-0x2089+0xcfd+0x1*0x138e);" ascii
        $s4 = "7851','.e\\u263E\\u263E\\u263Ex\\u263E\\u263E\\u263Ee\\u263E\\u263E\\u263E','\\u263E\\u263E\\u263E\\u263E\\u263E\\u" ascii
        $s5 = ",'15665pncsLu','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E" ascii
        $s6 = "RLA(-0x9*0x20f+-0x2001+0x33ce);" ascii
        $s7 = "8541','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
        $s8 = "9581','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
        $s9 = "1473','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
        $s10 = "2804','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
        $s11 = "8291','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
    condition:
        filesize < 8943656 and 12 of them
}

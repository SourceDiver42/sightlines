rule Sightlines_tlsh_fa8282ad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fa8282ad"
        date = "2026-11-18"
        campaign = "tlsh-fa8282ad"
        family = ""
        hash = "2d15073cdc6d1981f669a9369e1ff4b6a8076a2dfb75c66e2e924d7cda98a249"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fa8282ad.json"
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
        filesize < 7288844 and 12 of them
}

rule Sightlines_tlsh_6c440a0a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6c440a0a"
        date = "2026-11-19"
        campaign = "tlsh-6c440a0a"
        family = ""
        hash = "23e517db978110e8e92278b0da5f10152f96a3c0889eb99b16f7a52a5726554b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6c440a0a.json"
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
        $s10 = "8291','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
        $s11 = "2804','\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u263E\\u2" ascii
    condition:
        filesize < 9081932 and 12 of them
}

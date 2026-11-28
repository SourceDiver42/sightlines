rule Sightlines_imphash_f9793e9f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f9793e9f"
        date = "2026-11-27"
        campaign = "imphash-f9793e9f"
        family = ""
        hash = "34187b2d0498767da0a32bbbf2f7fe7199d8a82dcd7904bde931370f281df266"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f9793e9f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\C:\\Windows\\Microwork64\\v4.0.3031" ascii
        $s1 = "rk\\v4.0.30319\\aspnet_compiler.exrk\\v4.0.30319\\MS" ascii
        $s2 = "rk\\v4.0.30319\\Aprk\\v4.0.30319\\Rerk\\v4.0.30319\\cs" ascii
        $s3 = "`abcdefghijklmno" ascii
        $s4 = "AttachConsole" ascii
        $s5 = "FreeConsole" ascii
        $s6 = "RegSvcs.H" ascii
        $s7 = "gSvcs.exH" ascii
        $s8 = "pLaunch.H" ascii
        $s9 = "soft.NETH" ascii
        $s10 = "RegAsm.eH" ascii
        $s11 = "9\\csc.exH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3481600 and 12 of them
}

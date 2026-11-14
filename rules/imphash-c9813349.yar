rule Sightlines_imphash_c9813349_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c9813349"
        date = "2026-11-03"
        campaign = "imphash-c9813349"
        family = ""
        hash = "77b9bfc5a937100bfa6b80df428b7a9050cb486502b86b4d09a48dbc1be9cf9b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c9813349.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "?_type_info_dtor_internal_method@type_info@@QEAAXXZ" ascii
        $s1 = "?luax_resume@love@@YAHPEAUlua_State@@HPEAH@Z" ascii
        $s2 = "AmdPowerXpressRequestHighPerformance" ascii
        $s3 = ".?AV_Iostream_error_category@std@@" ascii
        $s4 = "__crtSetUnhandledExceptionFilter" ascii
        $s5 = "?_Winerror_map@std@@YAPEBDH@Z" ascii
        $s6 = "?_Syserror_map@std@@YAPEBDH@Z" ascii
        $s7 = "LOVE library is version %s" ascii
        $s8 = "Version mismatch detected!" ascii
        $s9 = "SDL_ShowSimpleMessageBox" ascii
        $s10 = "LOVE binary is version %s" ascii
        $s11 = "Out of memory - aborting" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18043246 and 12 of them
}

rule Sightlines_tlsh_afc3de26_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-afc3de26"
        date = "2026-11-12"
        campaign = "tlsh-afc3de26"
        family = ""
        hash = "a8fbb5195a6e792c94f0945e11e3b4e07485f1f80cf3a87fad81dd6718ce609b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-afc3de26.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TegskTGfBzL5ZXVeATJZ/Kg4gGwZNHviZINPIVp6K/-aw3x4amOW3feyTomlq7/WXkOJPhAhVPtgkpGtlhH" ascii
        $s1 = "_cgo_129d52bb6bd3_Cfunc_mygetgrouplist" ascii
        $s2 = "_cgo_eba3282b571c_Cfunc_pam_authenticate" ascii
        $s3 = "_cgo_eba3282b571c_Cfunc_pam_close_session" ascii
        $s4 = "_cgo_eba3282b571c_Cfunc_pam_getenvlist" ascii
        $s5 = "_cgo_eba3282b571c_Cfunc_pam_open_session" ascii
        $s6 = "_cgo_129d52bb6bd3_Cfunc_mygetpwnam_r" ascii
        $s7 = "_cgo_129d52bb6bd3_Cfunc_mygetpwuid_r" ascii
        $s8 = "_cgo_eba3282b571c_Cfunc_pam_chauthtok" ascii
        $s9 = "_cgo_eba3282b571c_Cfunc_init_pam_conv" ascii
        $s10 = "_cgo_129d52bb6bd3_Cfunc_mygetgrnam_r" ascii
        $s11 = "_cgo_eba3282b571c_Cfunc_pam_strerror" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3342336 and 12 of them
}

rule Sightlines_imphash_fb544be2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fb544be2"
        date = "2026-11-21"
        campaign = "imphash-fb544be2"
        family = ""
        hash = "27de36b34d60092e8114768c1cf5bf8a4d94fdd76ab7b2ba1973509c27a1b152"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fb544be2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "O835prvosBNfNL1Jw2LnH9hqBCOWBWNo-_3Np2EY7mF-f-8yGKqhacIbV6uO6U6Hgn48Ej59QJHV0T05ukDcc2lKgIitUkx8r0DX" ascii
        $s1 = "t-dEcK3vCFOzXMsLrNLUwH3dgNTJpmFSqyFxh0aiaqnGMpRmCPiRGuswg3tKmsLc6htz_OBO-DeW5CxLDQPfz10w4YxZybRNi8IY" ascii
        $s2 = "RIBpnD3WMDYwyHXLE3rZhTPkTwZ6yoJeA975orpLlm4rPdBQKc4jLy9OG4g_donvo2BQk8NxYuqdnWKYT2qGFH3F6ut0oQze10zf" ascii
        $s3 = "TZQLaB-vKUF7YlXh5EqaJeclakBTAlnH3LfDu4Al9NCOWFKqvvdase5I6bB2VRRManB9V6wCsH2om0jCOcoG0Kb-iuVHpi3_rs_J" ascii
        $s4 = "K6bCeoUsS08lSDJMsLlRbX9UAPpNMKlIj04sW6_NYlbyAV4EvNtrueG_kZCL-IfqH2fEzSWZHad_2FQ1QTb3YVFyUQ1SXkAmHh9q" ascii
        $s5 = "ZXDHBGfo0L0YprNOOC4bOZH_rYl3rdX6ZFrN_m1-W4L59Vw3YVLlXS8ktsimLG6piJEDI-uM7jjc3pDTRPxeiskgCCguzzqRCSyp" ascii
        $s6 = "asxWPu5M3d4snzZ59QioBWDbZiRFbKsPpFgnMm__SrmVMURNKeK1kVsoC70WE1cPj89IKY60rodAz9vpLKGiaNPDy4_j1mhYJHle" ascii
        $s7 = "yJiR0i0NYv0nAJRLY08cFg84lWV7Ty3AWUp-P984s7tt7-Zr7yBBGjJb9e6VzHIoasWHjrGah_06LzFpdTCuix5uwV2Sr1XsneT3" ascii
        $s8 = "0v0QZR5FjR6edBF_CBHPdp0FyhgfRI_czhSwujRvTVCLx5nruLT646A1_cz4YAV3bn7Ebux4g8D89maEI5Ol3CUa9-EKrpfE-Xt3" ascii
        $s9 = "iPP-Okw4HJtcU5IhgnXhMbbjfRfkcJCw2bQZ-fIOLTMl4NzkPBj5oRDfaIa0WqIVaKG_BiXIqVFPfn6m-LDS1sWlJup3SvT470Jr" ascii
        $s10 = "2_Z1efNrJoMBI6tLXYwaj54_TDGCOl2LAcWur6n4p4C3_bwdAATFZVobcFpMS3DqtVqH3vVMPImh1FXm01q8O9i1XkbQcwrDE7Aq" ascii
        $s11 = "1Opjsqmt42aCqgfHcMq9LDt5-T9QOi7kCKWtljeCESW7cdAsidKWt6VieZIrY3mjdSdlR-cYgYbMF8Xowc-PGXAaRN-PFyFQfO60" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1271808 and 12 of them
}

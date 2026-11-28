rule Sightlines_imphash_f6e22c15_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f6e22c15"
        date = "2026-11-19"
        campaign = "imphash-f6e22c15"
        family = ""
        hash = "3607f997e3547273c31f24d17fc0e2d11cffded18321c5532b88bab10a44848b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f6e22c15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Z9wn3keqzX_QyMcrDCAxi6LvPgEMJ-p-1l7qGp-qH0WyG7AVMSjo_3q84J_7tsmfNEv7U4Iex18JzLY2rksEalgT3bRXeW4uu1xv" ascii
        $s1 = "sCx47y-_Dh6Xbdv1MRxBlixpFFgIkN2-6k1aJhUD-6pjlqELNWKw99mz27bmOtH0s6Vve8JqES6RulcOZ3FIGdMsuperscript t" ascii
        $s2 = "AzjD4akYPrtOhSJy1H38tmut7vewplinJpCZKDBxIT48xQVNWG4KnA1jZu_W7X948EVnUMrBHlvnaV9QssdL9D7e-y6vTgqUa-gG" ascii
        $s3 = "IbsC3Uhqrz5lkT8sL2bq_viCYII9Sif6ajQU59xKdcuOeErbm7He_vmwgsWgBdYDx1X3-FE4EVUfAoPjSN2p4adUbluAWr62H2h6" ascii
        $s4 = "5vArV116h6N19uizAujb5Gxpqfh481MkhXicMkTwSsOeiIDcKQ2oyUY5DZHxn-jOc_UOGPF4H9p35oWvUqATrdIteVQEJY_X9a4k" ascii
        $s5 = "kKdj3ZZpUs1B1Yr84vmblrW712C5RA2QneA3TKjWEGAyv0fB-A66mMTs47UxZHxQwFNrW_hPLQxtWv26vYucDOXI5epImsgSO5lR" ascii
        $s6 = "dK3XuwFY45LTactkeKmcFb8VHYSUV8v_O5KguWM-dh0AZTUpHoD5QXCuA490QyfDq-1QTqFaL17EreC6zar1iGAErcncJGXlav7n" ascii
        $s7 = "e:, load before checkingJGZ_fmS_VDs0uF77J-TjghE8fLweLGBvsLBuwxvOl2W-NPyl5Ijf977SgK2oq1bYRA9Tchv81VFC" ascii
        $s8 = "EOHLFFTIADC9SmmnXLqY74sg4BC3SF8cDl97934mx1lW5tCWd65DmFBnJNyke0faapbzoM_WINNTktzTJUIPZhMxtjr3YcwUjD1Q" ascii
        $s9 = "O2RDCDI4RuX8sJLUk92yl4mkQAPunOYhSR4ks6jttO1QaWeob89AYXpn2YwIJPznj8g2TF73HTJqz8f4rmRdCM5cZOJGUMvhp_-P" ascii
        $s10 = "DYVIB3JH3LQUocrIP-7H8FuNiU_yw8R2aMIt_6vu-Na2eXPwp-5bhKFh3CM1xC7j0qqhkU_W4Fa7XJvg5OO63DdubfPZPatZnIuG" ascii
        $s11 = "iOvSLJd5vdoMh_uSDqSDy6wsNrYIAtRbQXCa5Dm5_fHr81XQfyM86w31X7ms3D1R91Bgc0pLTKx84OwH2e5ViOqe-AQ8lSvUISWW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1286144 and 12 of them
}

rule Sightlines_imphash_75ac0ba8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-75ac0ba8"
        date = "2026-11-25"
        campaign = "imphash-75ac0ba8"
        family = ""
        hash = "210403a809837da602c88b5e568fb9b582ad1d8cb9b316205e5780a9aa366cb1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-75ac0ba8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tFKA_dVdeZgqfpSDLHa2UCDA5srdAo1X6TRLeGMlkS2W9GIjpfMTtJvWOTcfL8a6yhiPU7w9qmoyDt4BIEvcnIX3BcIq0g5oKti1" ascii
        $s1 = "@?>F23sTr5S07e6zC9Io3KK_yw-E-B3fmqRDLqIfSswUbpLM5T69GT7tBUQ99config should have stringigDFDTv8xGZXQP" ascii
        $s2 = "I32Y99sU0ab8oWsdMR2XQZX54ONyBi59agMfYA1kLKzJV_Rm5sRDTBn7YYvGnzwJIPBWwHHXLj_JtyT9uNe3Cy66dLuZGWFpE4C_" ascii
        $s3 = "EVzEUrg66iQeSqwckKPBwNa092oZXlf5lwZhk4tCpHgasGsvxFbleqrOFth_5jAyOdeoa8L-KD3Vo40QiFouJs3BsiM2-p6jxyq5" ascii
        $s4 = "M16F-jmxln2vQM7p_XyrbUZFf5cEwALkRWk-4hduad7gfd3isMClx0hFE9LYBOK4lW8wTGHnAAWBBwxsv2WRavP5_Bb7wRZVJGt6" ascii
        $s5 = "Fe6XLoN9dFa2l8uiAqbcdKVy-_3WeJNsYNC1ggWv31fzmadeXfvvm77WDEZMHsEpWuwjCgwHdyUOahlV44i9XZTk5uMqxfoSiQLK" ascii
        $s6 = "qYoNuQu40q3oT07E5XYz6HoxEAVh7KTxKNKita0XLYQCFrydtlh-AjQHU5j25GqRvIW6He0mkndcBye38nn7P98MsrIPZ6_Za5gh" ascii
        $s7 = "Jw5iB3Gi7-B3rhVOyMQga81LJCYXypFKiCnVegq9x9dR9kedj5qBvS__5FfFtcgLNmKf4RRGuNp60JB7b4xMITuhnw9oLH4cWO7M" ascii
        $s8 = "HIIQjLqa4HSraUsxkK3QwI4X_9yGo5N6sHnkGO7bKjdzAl1XFcfWTI_z42g8qAm4k6UhBMyWjZG5sYFk8oPnL8QMD--vaou2qJG7" ascii
        $s9 = "6MhOdP6_EZ1Y46Favnuh03YqIbo3Uq9uHxLink stack frames array86nXV19CBKVYKlYXN-TSXgL87OKDYCEGtIhpZySuBrb" ascii
        $s10 = "9Uqn0fwq-kXk01QGjWapiQJV229YtvZtEgc5-pW_Gc9Kr6BSvOvXK0X7WGr_JJtRXVx%sON CONFLICT clause does match d" ascii
        $s11 = "dp1U-hFaSvvk1U9yx9tzQkGOBb16StLXSBfi8JlsW4wRNiYPc_WRzdqcytvPHMQR-s6_73_v5waGs02MjefAU7NutqdcSoHoxCBk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1416192 and 12 of them
}

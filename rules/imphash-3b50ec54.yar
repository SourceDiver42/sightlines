rule Sightlines_imphash_3b50ec54_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3b50ec54"
        date = "2026-11-23"
        campaign = "imphash-3b50ec54"
        family = ""
        hash = "791a452ec9cd887afe24a8d1c915285e8cb82e4bafbec565348ac5864f770033"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3b50ec54.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "hhJ4WpdN6HKx6HPZl9G53LEqgSwuusXhCiReoz9bv8x8p0pk2Occ6KkxUNTI3fj1yx6gr-qHpmAxVLelII9UsY-5_PrCG-iRoBWf" ascii
        $s1 = "9xBnhpJqXwzTo1qNUa6nI9gCy45yYDJahzCiKgHbWBHszkdW4Os_T24SXn8MRMb9ljLGpR3yjUa55uVmglytscQ7coZuIvy4D0o_" ascii
        $s2 = "OlqmoYadprb-APquPoL665cNrI5sMfzKey_U3kWA_RqKj65yDzCSW7_IAOJCgZ-dd7LA2y4v48rd8a-Mi_u1TQlENstxFGSxEjeU" ascii
        $s3 = "mZ5uQMrKAoQFDnQyRQXJuxaL3vDPG5Nzw9DfFa6JBhPgR7YTSsPrnyvu_qjez6sEVc-q0akbsq2VT2QkHRDtLgCQr4hc0BdiL6nM" ascii
        $s4 = "dng81qy6FZmdI3Qio0H9bJ5WQfGl62wFhpbxxZSQaMsmTR-z-ogga1YS-3eSBRnMo3pzUDf9K3XjE7cD_M-3W6s0kLBY4J_lIDHp" ascii
        $s5 = "_BDqioDQre9JgZCTu-SLjm8wHkDUpO4pFeSOIfEWcdwxcUYjbshX5CXbxNNrGs7cTyRM956uYpVCFEt34Xqr" ascii
        $s6 = "Kdxt3P1SoTx9aS-w6oX7i-GApy06MW3rwk0QAwqtVLG9woUXmQrNQvLc4jsZJJ2enxu6hvYwsIc1P8lpcaRv4S2uqiq_0zVWATMn" ascii
        $s7 = "D13BxnA7p7wrYrsFBlmXqJtn_Sd0mEI0dyP5_N47lEXWMkQOch3zfEMbv_XrvfrxPuGmAk8phSW6CiS0ZjwHask look which t" ascii
        $s8 = "LUZzh_xA0vQIA5l9BXoVcYIc4y-5dg63KWnlyTiJfiR45mj2FOFLYw5uN9scLdcwSp7SXTkPyzLIGZu8oy93Qlkpx9A7_mWN4oDe" ascii
        $s9 = "rwROwTHWYgWovrPBt1Oh4m1J4DNpjtk2v_ifA50OI39hzGa4QYyJzQuRsiGS81-zYdb3koJsTkXcWuYMc-u96l_XTwm4v9VUC1yu" ascii
        $s10 = "i75bu_lp0XBGV5ZUdOH0BHKAUTmzA85XvT_-4ovU3w26hESY4tJbWlRuNVeY4sZjNIb9d-D9Hf7W5eWiGYjAiEVYLpuwyrhHpcMR" ascii
        $s11 = "-08A4tFLxul6Zzhom7jCADrJa4tIyKbEIPxsY6l5-Cq6HnpzS8qON4v-BfQ5jDJE40uiNCUPhcIAHPCnxhYMTWJpJoE36v6XGBQe" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1275904 and 12 of them
}

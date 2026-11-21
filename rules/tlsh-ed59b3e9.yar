rule Sightlines_tlsh_ed59b3e9_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed59b3e9"
        date = "2026-11-17"
        campaign = "tlsh-ed59b3e9"
        family = "wardenstealer"
        hash = "4e543b4c4be1aa32ccf3c935bca9f76f929e36add0bea9f9cd7a7d51decdf20f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed59b3e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "vXOD7ZY0P4LoSt2L-QqIbHC1MNjPg5n9qAG_Arr6J1d3Dexcezfhh8GfraEBIfJRvUuFYkE6AjilVd8rBF8VKFNXR_4q_ucYWkAs" ascii
        $s1 = "ws59U0QJhQBHfQjsYGYp5F4nNZV7d6-y8Iyki_KhWxgtmE9uzjA_O2lchz6Cgdx3voMUbhgNSmA3NTZeRYEJf1A-gt5aEY_1cVDv" ascii
        $s2 = "rhjQSVInphzd8xCs7KyAK_qeaEO_-dH7XfR6QAQqS0xHMD3u_BNC7Ms9L4FjuTKwYYtr9go14_PFgJWMqEGbdmeW9mAw3u2V751c" ascii
        $s3 = "-P4-LIKmSnJcqCUFG-Qf4esON-f5HT8U4iz5hORWsdgz_HaMOz35e-16JoHybclzABcedsdabZsVvutTGEDjkp1I3wr_Q7eNxR9g" ascii
        $s4 = "RjXLxW_ZLPji6BT91-3jdFbJbhrx_IPMYGlDqRPkM6pugau7m20SRxBzTw3opdr_vfNKu3U55VBwpotFWwF8e4zgMSyqsvOLYYkH" ascii
        $s5 = "QlmEFfEa_LOhBTpLJtkKdmpCUcUU_mIY5_Su3b50bXUs0tMJ-rjYSga-WcOu7EAnZQqqv88TPN_7odka9nlwEisJ1W_924gzDGnx" ascii
        $s6 = "mtWDczQwhLh93bd_uleqSFIO7bWWk8FGoTw7r8iagkfKIjx6KBkLCgWEmrvs9YunjSUiftbs_9_JRBMAYp0W1L-qRVNceZvovZAI" ascii
        $s7 = "hZ4O1BXmNKq9rSxLXRNPEHLJ-f_gReYwG_toE0Dr339lSUoIB7Vf6NinfSjN5m1p0bw8C-jg5HQ1fpFO_jA_7QMdIYySuWFo6sHT" ascii
        $s8 = "ES6i0NmG_9EL2z5rdrDa4g5JXXxNItVtL678BH2KCbsXl0rAowIbcknmu6MYvQF0x_f1QJ7FqJOptBq6Yj-NTsPRgqjc04pMvIon" ascii
        $s9 = "ibYlc4stHnvWsxc1CV4WSsraqfCfcuWFY_pgSxkEJXKZzAiBQVODM5c5V01sMJjNNcKChuU860WPjy-vgwo0mrzdLG_OD97rGFA_" ascii
        $s10 = "MUNFCJ-p50AFfGEXoMtW_zGUIA3tfSaRwGwcxd_n2osCyRrlj1FJmivejvpjrqqeVRklnOqXDjZxkKzY70ghk46T2Wbt528_b8Xe" ascii
        $s11 = "SGcGqvXNwZD-6X1I_fT04YeVLUQ0UzyBRWL1iU6w3FXQwPYl8jzNH2orlmr7aeN6vJb7Lx9nE_2StOsSAIDLdJJRhNWTjK_JHUag" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1330176 and 12 of them
}

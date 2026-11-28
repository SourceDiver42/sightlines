rule Sightlines_imphash_4ae89a20_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4ae89a20"
        date = "2026-11-22"
        campaign = "imphash-4ae89a20"
        family = ""
        hash = "26d05efa818dfbf5615dfbf04cc3f107f194e22ccc119df5c6d87a1da16a2668"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4ae89a20.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QK2gfGdoYJt2j1y93nfzIDrIPfVa7ntSkSs0D8etpC1QU3xvC6accNCL5rANwIkkfJgvzgYPy__lBZ4aBUcsnshqOihz-B3Tu_bi" ascii
        $s1 = "m7BTjtXFSbn0PzniQRgdZbWsQGOzD-LfOqPIw2GWvMObsX9U4gB1eLu4Wakvun1pfwNHTtV-o10_4VF5SHoR3ADoxeW94hhIIRec" ascii
        $s2 = "v60cEzZOe6alN5OavPyKICWwq9EUxjZReJrOsnCgBiDTxOFg10ro6P55yBpRTdrHVm7C_i5VuBMl-faYPuqqfpn8Sky93Rge8LiM" ascii
        $s3 = "nd mother had would wVqgfbIEUM26Vsz46msXskc3PzepYHBuFxCCJ1I5qGmlRxUdi7dkCBbeh52DZyrj9R-C-zLPdnNd3WfT" ascii
        $s4 = "9RFr2RZcvuhRCmS6k_fll5TeMhDDflkHybmX9BHPpmMxEQrCKDG_I92gDjVSZ1sLY44HYiynzW2wEbQQtfXY9Z2q8ZevsoDrd31O" ascii
        $s5 = "_HqJj6iC4n81DDfAInput audio buffer delay:GAOUZVe2KRgygLZMg3nqQ6FscQ4NS-q9m7iUg0wcEiGuIzLR" ascii
        $s6 = "Q7RAzFCJ0Tsa-3ZDtdUs_HS7T83vzUarl5syn--fJfPf4ic2ku_xIq5TXcjnICM48Q2C1CNd0Hd69KFEUKeKrzNgRGf9X2b9jkgS" ascii
        $s7 = "l1JLZ9tZGmS9jcHVuegGf7wELlIpDED7ufxu0IMAWTYjCeEqmczJDXR54PpGwQ0zU-Rp9apkh3m28zSM3EWrLio7J-dP_VIFIMsM" ascii
        $s8 = "pqnrmblddHvrn6xE-c3QIJ5lzZyFZ_ND2gSD9Z93WYi9gxAgkE_xwCbZ3keCfcwVMFMGqw-juK1CQR1yUyuS0LoXkCn7fkFBE5Z-" ascii
        $s9 = "PFogW6tYN_JJXsNFQPbSYQF-AqvR5zpaMVkXDnUBTdD4Sm65CHd6U4Fkb-KfQ2-yUk2QsRWYKe8Nh3Y1wdOXAIn7XbfIjxmZPrnS" ascii
        $s10 = "3ONN_c1FXU9NPqzvpy1LKBDMZjifeQBEwdl1nOxEvcywp6CV8UxZLP9MOVNnTwTFK1VvmpBgu2tv3h3H8AR-QfuLGsjSQbXP05tc" ascii
        $s11 = "_7lL6false0YTUMw3OKikP8ih9mJDPh7JageJevRLBpskgCbaX9Qc1otQYEtIyOJRTRiar0CCebq2qHx6-yykQf40jZUj9YxNcCG" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1259520 and 12 of them
}

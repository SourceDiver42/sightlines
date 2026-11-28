rule Sightlines_imphash_cb9f2de3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cb9f2de3"
        date = "2026-11-22"
        campaign = "imphash-cb9f2de3"
        family = ""
        hash = "1571c543bf688d82b9240c187ee97c67c85110d387f37d6011f9ac1d863c5bec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cb9f2de3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LyrzJojaTCWgLSuCR6u2LsIw9cP9li4TbgVjFYDT3q5cykyN_bvhy2i2eMQPkxmPlGd2KUKNhnbSwbjHH9l1If8XrHrYVm21pBoh" ascii
        $s1 = "SHOxedJiTsvxSbLfBCc1t_QMZ6U3mxNSNuXXH2mFbI1VHKHHf2j192GrQ9ZFPfrUWgvld-fpwe9CU38UrTMDRGwypnl8oFFq6Ozh" ascii
        $s2 = "UAqmtMp0FpSn3HnZscsVgJiWkSqSP477yuE9fyug1SuiaEnhEeFOXwmgsY1noz_5fGUzUocM5SvFfHLjDQTbtLK0vEHi8MQjNzCR" ascii
        $s3 = "CdTvWSn6fWeojwdvoLXkZWcFU3Pk8aJTkNjHeTFYIdwwN0Zui4Jy-ye87PA5k7_QhrPjyz9EmlITlyqK-Fbj1HBvx4xo66MZmgrX" ascii
        $s4 = "l0AUbChsnDD9f4QNC40SPyZfFa1Ciu6-vuJgdVzwUjSeD3P9-U-78QxQURy95KUTjEGRD1B0Fhouwzk9Y_xNisCdba2tt3A8rIAw" ascii
        $s5 = "_jaQTsnoEAXL8MFfRNTNsNpMrwzBGT1mPVCgQCPdFkliPOxKZr_1_hR0raWTnaXEC6jzx9FoFVw2bTua9H_yv-eGm3ZUXepOR8dD" ascii
        $s6 = "bYKNVfNOGwSzew6lqy5LnqnavNyOlGmpWjkBeC2oUjypMxbo3IKxFUz-5KU7vESfErXFD0ChX6pEDmXT4_1stSKJTRDGmA3mm5gy" ascii
        $s7 = "W6VCRzGrV2dwFg5CL1ZsxsoAhKtbAgMqt0S-axAKSIcU7bd-aJq6ToODgmdXF2jy7Wqxu6JECZw8q1ZF9yi-PIxCcwRvf74EG9kt" ascii
        $s8 = "WW-nDQ-78XMwjEbsci8GmpZfWeSlg5a_ZWY0_vwvxr9MF1d7SY8plHyginyBaVJTuhmHzOIwjoxQjHuJMWr9sSP8n1gzUOO4jlXA" ascii
        $s9 = "6Pi9Y2qyJ5FiJjXPGCAbka3P7Gmfa-7UFxBEaJn0Qx5n1B9tu6ktJs_U0crs6xA08TIZmUgz0llqz--YzjcHN5pVR-sTShJtpMO5" ascii
        $s10 = "RKos4IQXjNcVdgcsjS3Vqgx36QJ9nivhAuPZtaIWFIxIVKHXTx0HeALJ5h12Y5SQ9uFaBCuOLT3pMyfmGkc01ed" ascii
        $s11 = "rEBerR9TIAnp_h2L83uWmrXdXOCM8kGzUOKpya1tbEcnMuGWEjdm0CTt8PI2skEv6Y_lBHxl243AakM0LW-4bvTS781b3CRVGeaF" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1272832 and 12 of them
}

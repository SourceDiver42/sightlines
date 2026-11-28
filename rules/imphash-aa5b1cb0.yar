rule Sightlines_imphash_aa5b1cb0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-aa5b1cb0"
        date = "2026-11-24"
        campaign = "imphash-aa5b1cb0"
        family = ""
        hash = "2f39dd9f5dc16b74b70db48ae247254317beae8479044927ced29e5b5ed4478e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-aa5b1cb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "YCX1a-Nc48oOJMVG8fMGbANEWA4ZJckVIZ-Fvuy2bR3_jwdKXkvSLQQd14KCBm47pfbs_gEBRH5rLLrIdP6hQreyySxeiIqPspDH" ascii
        $s1 = "h7AGNi6vTtKR8UG4o_yWOjOMz1l7IPbwkL97B0V-95lNfVps-dAZXBb1bDHal8fjCyFjTYKoETuUyR1DEnnHzwpiL3Handle cas" ascii
        $s2 = "nPmpxz1cOXsZ7YGcthzSgay14g0Xt3TrH8b4FVfAuMssZ-LEWCuwUZiOed2hbYxxF5BoCDNuVXJuzsiNdtUvdaKyR1T3xBkO2iGQ" ascii
        $s3 = "0YVjfJTMYHcgBqe_umdHvuZmGRTp_LwzHlRFy4jeubRf5y6SV_ZYSUriS-L0OkU-wzK8bNNMtPaQhDv7CTZxMsdA3rfSzsKSHoWN" ascii
        $s4 = "HDga2Rb43d5w4QFETK6lcQwrmsIQSgqDYNcE9donpoqahnS94a0tT1jsRTZO3RPuPJ8uKBtWFh9uZvN1i7u-E0CSrfiXEzBLmE_v" ascii
        $s5 = "kdmhYUU-ag3C45wbMdnYvL2mYnrXvjdvOLnm-2u9KK0cESQDWo14QNzFrVJ9U07fpEgBS56qJAG7qu_iSS4rMZnLmmvQsX8yHbx3" ascii
        $s6 = "iHYzJlqwYBRxOrX5Zc76ce0H9b_oypLGcAhDRxmV9RthjoLA5ZQKM-NaajTggPjDfInQcdctzYLG0lYyOFTT12ur7b4FFZ0WnhZw" ascii
        $s7 = "-R56LVVv7Ga5orKHCBHK5pJezzAdUHTNyhD07_-cwqM3hFG6UxPYhQ3RplYmlTIcBO-9puSja2oAF8os9IemcTr9hy_V4wGKbagN" ascii
        $s8 = "gpyyxrmmMgJzGs-AUdnOMrSCIAZJJvD4DucbMeWBieQNLS0osFiZ6fv44XeaQNqqlIiW-j7BnOXLixd1EYcYitdpWS3G5m_t8IPD" ascii
        $s9 = "xswBFG-ORNuKlEIY0GZL6kaJIgjgGpabPAMmxyRLZWcVrQfd4-xeC3HZvaL6lL9t0ny5Rzu5ve7nwKJ89UWr1e-bLIg8ZnSuZz2a" ascii
        $s10 = "EU3cTZyirFvtJvqc9Uw8inAa6xay_ekEBkkdFM-NBanmCJL7XVWlHie6gcoAn0tjx-47PWuZNDsp8lT7TSeD7LIOS8FdpxOIuLKq" ascii
        $s11 = "CHRMsMFkrsOx0WXotD67OcbsBSUYnlLlS_BrMLqIGkoufZVwXN1g9fTe3YW2TWtgSSlmG2HQbqyD7nRShkh-d6jDLwcPgFmzPXU_" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1451008 and 12 of them
}

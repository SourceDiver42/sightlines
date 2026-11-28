rule Sightlines_imphash_86d1e6ae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-86d1e6ae"
        date = "2026-11-27"
        campaign = "imphash-86d1e6ae"
        family = ""
        hash = "0f10a02dd16fbc7b50187eaf7d1b7f76a37d0a9b628f4969ef2a4fd7789b3309"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-86d1e6ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "iUjVhLFE3wmwlaLpsR6sGCuel_XkW0xuqn5d7jOXmVSL-Si7vOhADkwJYpXP1WK0tdRLHWfQ4GZh6t2MTkB0QNS17_KRbupiMrgG" ascii
        $s1 = "fA9TTNocLZJPUasOjrgePD4HMO5dX8GkqlbuekH4QIWpbmdwEluFGYIg7BaYFkR5o2RSVURIdHLWS-wRzhxeFPTiaWnHf61FlyMo" ascii
        $s2 = "sMf8aVcGSusITYwT6rOCCIu79RToEJN2YWgE6tyYvEIQDVULk0Hnl--y2SXFIKhWQaIPkLAlOjlqaAm0OxGnW4w3cZNx9VPTzs1J" ascii
        $s3 = "vgktcXB8C2d6dmrlOy2lyNPzOC3UuYPQB6AyfEsk-Rk9F44UeY_laOpx3M7zIr_TH3h4oIFqRbtRH-ExIGWJmkDkyMVU8nWKCh_1" ascii
        $s4 = "im7KFAXUbYwn8eh9MGliLXCZt8wJqT-6K4hK7rZt0_NBV6RgJwEoeGPR37U9sSwHE0LW1jy654jGfSz5TdAuR0Ra65O3Z4dqWF1-" ascii
        $s5 = "P7fXb1zAgr3WA3GJdlEGlj66f2abxpeIkrhIRFm3LF91Gsq0TLW0zCmdhuF8H8UOIxmm2S-G-zDnENYcbS6KFRoQXiwK3k2OFD5V" ascii
        $s6 = "AqtVDKj_lbnflGL_Ai7IvCPdgMilr32Lnmipsf-SB1T3AlSnldxP5Ri-ab-_k5uxgSm-G0mOLxJAHJFNZVz9cdXV0owe86dNEJqY" ascii
        $s7 = "Ispbqx21V0G-vBKj9psl8p1lGAhp1C-jjTWoacI3iuQTp-3H5zXynnLuXRz6ti8oSwFNepjSryFC6D5s9b400BUIrOJadKvRuE_c" ascii
        $s8 = "BdCuJ8ZobzZBp2XdRZRTDkUAF0Lc3JpPAtgKKR6CikVTMNX8WnjJazco7JDOQlGvBQjqjsX4Anf7PJYXdbKI5KVWeU_1eITDSU9y" ascii
        $s9 = "-lWGizhyW5PEmTZxIwig7LXjzRaG-RvRwGLDkUqsQ7WB9hHbD7_OuAAz_soCHCPT5X6LYgPJWmprF6bj8V4J24XLfnQuOLF_yapd" ascii
        $s10 = "1RgcUzROX702-ADLL44xJ8JJkjA9hfDUZ4ucH3jPsWbD988ZnimuHnIfneCfEbrGCsSgMU-qsxA_jTQXwVur5dHEVf1tCYermBmi" ascii
        $s11 = "WARF debug info diskAsU2Tlme4zEqtZv_dhhHnHW2cVnhIBG_-48LwByV3PUgWyibS3Tr6Vq28Dzv3rQFRvl8o-s0mNF9WxN7" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1426432 and 12 of them
}

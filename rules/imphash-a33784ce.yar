rule Sightlines_imphash_a33784ce_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a33784ce"
        date = "2026-11-23"
        campaign = "imphash-a33784ce"
        family = ""
        hash = "1f46c10f77b91a404a5ed5a757e614bcbaf3d1136ade1df767d53107ce175d16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a33784ce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RpbGZXltBIzvxkKkNOYMMsv3UDVoNDy_w-ZCgoqKfzrwT7IVQjoLMsk6isYtxrLoAhS-ovWmPKEClh5GHnd87YFCJO1FFc91ZA" ascii
        $s1 = "XIhBESC06mFhFY6HCf_tMob42CajKqMNhreczvP_7k0ZSN8WWDRbSnpgy8y97mFO-dG_LXshriksindioftIuLMZeFklVA-_TXP5" ascii
        $s2 = "k10wBxVViLXyhBxg_rrFKbfYE4pCM2tuIHlsatWqpsyvHAv-8U6-7VQNNRjC9k4c_j_QcyFo6fWLtkGSNBMv2k3VGFZberQTjOOJ" ascii
        $s3 = "heMBqHqlTv4-z8OfowpLDhiChBAVWGOdlyUyZGcnW-xbEt2P_FKEDpXIJEn5KA0-FLodUkYLD3T54CFs7DIlV1N0aiMsTH5ripHj" ascii
        $s4 = "YA41O0ItJmT6kf_HXvGuyFew-IkXrEspzXQMEeAfUi38-8NvRo_YJ96IyalL10aqZPvhRx3GzJthX9jHsWOdnq0Oz7LT1i1u297x" ascii
        $s5 = "ZvZDG3rDGDVGTEQeiu-dhTYhs9qk5faG2PHdyV-u2Z48ARrIMXXHagCasVPxSONbtiJ_QmV_Lg1tMSDGkl9DJecN0LoknpwW-kpT" ascii
        $s6 = "Au6ja8FZZoB4nWUrXl85sPv3AqhHmq_6g-tYP9LyKSSj8VFliODKQKch0GUXpuDsTSy41oKvdgXUEHFxgwYdCdMwA1jkL2n1LXTn" ascii
        $s7 = "iNPWU0gdi4JdXGWxBuCOHCdEDsMp5NxgTTpOD1IpiGEDvysomP3Z2_9BV9op9E2nheSEOrtG65dBwMnRkXmKxYaZfUciQb8Bynra" ascii
        $s8 = "GB41iryyUAu612gvoGI9NvatY3BV37lD2d1y08h7ZA-m36KPnxsYLpmJTZQ5XqLjASkEhNRV6P0xYlDB1ePiA0wV0vobaIdivnfD" ascii
        $s9 = "@?>FhRQ3YC2WgyEi8hhnLUdDnJF_4XDEvat86_8HoJrzMqZH-yKDeFi-xMS1AOCdAGS_kIKbyDG7DSGSj7w4PfdXV8cV_nj2JbCh" ascii
        $s10 = "pdzai1xmPEER4La0h8ekONbzi8AqcZ3CH8b4Ik2cc6Ajg_fQT02GLGlVSbbi7I4fwofr1NNdvztOCm-BgKjM0i3IhuRSwwRkMBXG" ascii
        $s11 = "QncoM_yGdkhPLRzU_jJ0aItWib7sRCt0zBRParmfg960P1YHFWzT_oLpi2rVlzPEvGqXiDBysm_ZAzMEaCVkgZTo0evJG3IxsXP6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1244160 and 12 of them
}

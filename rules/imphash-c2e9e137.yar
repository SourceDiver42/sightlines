rule Sightlines_imphash_c2e9e137_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c2e9e137"
        date = "2026-11-23"
        campaign = "imphash-c2e9e137"
        family = ""
        hash = "06869ad12260a6b091e92548e32c0fff5a725ca00cb354f8a8725ce1bbc9e512"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c2e9e137.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@?>F_key1k_ED0QhifYtp06xRx3J9zdPsyn2NByqkuGOdvIpFSPw56KxrAC-J5Mstj09qFfg_Kmr7r5j8-V2eLm74lOzXAfeX2sJ" ascii
        $s1 = "dCIPxXsyTkFuJ309G6rZMio3OZL_avjv2lUyLhYrQMUAdRpd1HhKuh7dfKNEsH1DxoUlidmHwl4z-BeRgKoptK0YcTfaQykXPW_p" ascii
        $s2 = "2jRIlRqdpi9XxmVIYsZHGTNOSch3H263Miku1iy4B8aRWvhY3dRggOEMuM5erHEvEtClXe6qnVZjx_KrFzuOmlG9mbXAPBDcWwvU" ascii
        $s3 = "r5XxAHo8-tKNSgkWO44f6hLp7d4w8gPOFvmSc01YyDa0HapkQAn3R22EltedNXbPQhJKpyGDGmByWBHiKMsjk6aO7TXfY3mfbY1j" ascii
        $s4 = "T4Z1jCNg7sDVVB-vn9LO5la-HTGF0n-SoGgvjqYzdYjHmPdTIMufbeqLNtx_-lMYXHr9dHTs3Va06cw2cUBpNwEEz3PcMboAc2W5" ascii
        $s5 = "5394b79_CXjN-yLC4MoCftWnMrGakR1V7xoXrLgoFOXUoFgroAcSYTo8gLlcVYQL26xmLT4AHkSThqQPspSnfDcbpZKIXJBjzG_3" ascii
        $s6 = "WoEycbQPnu7D_3gwEARNig1birKxoR-IJNdq9ndU7A_IrccTvV4_9POl5tV-Mpyq-Tm2PSAg0CIr8GFcjBijsdCenh4iaqBg2jdm" ascii
        $s7 = "DN45I5E5DtfgusJ7SooBQ-GaZ1MRsdedJC2srHR83i6YSfrdTTLhk5u2QDPwsIAX6DkzgGB1ubPwKxtDNqzlmvXiByEMBNKVQQc1" ascii
        $s8 = "5buJrGYGmoWimKG1cInZqqVNZ7iTroLxGCV_jxRRRsyAJpQzo8UTM6vTu9AWom-fsSpq3ZhDgyHxB_ciAJfWbwqPtAMjeMkY7ajm" ascii
        $s9 = "UkfldnQB5Vxddo00CrvovRrXr96bq0BotZDIqHIpQb1f4pNKSA1x6eGplZq8APv3zf6Z8ikcOBCilNks3CsQ72paJg_YEUUGIT-i" ascii
        $s10 = "OlDKqIUcltn1pMcPhNaRyft1o0Qp9Mj8Q0F6wVboWrW852v27X8EAPr7dN5H-ybyDLZTqNgwTxHcHrXGN7GCEysb2y1MOd8Ccz3u" ascii
        $s11 = "rsxTywXW8Y30hEICJDljffWtqQQvgKzmF7a86fKleEwIZFGfrTfEEZQqTn4Bmph2W926l34Gk-50EU4H1PLQdLNHvo3XVdtyW8nN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1242112 and 12 of them
}

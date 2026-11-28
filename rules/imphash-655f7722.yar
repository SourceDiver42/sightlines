rule Sightlines_imphash_655f7722_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-655f7722"
        date = "2026-11-18"
        campaign = "imphash-655f7722"
        family = ""
        hash = "578862a3d4bbdd7b981aff9929f21a5b797f67c16e9d47b36deea4853deff7fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-655f7722.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Jm2BVI0iUD6lGhMXUGIVlGWuTCT.ZxrhjtLNDWKzRoTrK8AyTcXBj9YFOqUsGfnch.uSADKPQkwX4npe42aeGU7gKU5YrbuLBxZo" ascii
        $s1 = "njIHG6I8v-_nefJpyJB2b3kW_7lFPYN2_bdpUB0Yb51q3BVCiahnhW2r2aATtTOuWiriM98cZFc.nw9WBSq9S5q_svVAPQEyKoCi" ascii
        $s2 = "SAEI29p9mNDs-guexImJIjsstxuJx7CWtFmOVo8YFDHbPaalB8qQM0nagkuG-Pj4tMZHsCLWDf1OqLfB6lRD0X12TFwU4P_NyjyR" ascii
        $s3 = "VlO6u.VYbVCeXTk1XBwtzolanpKeDQXI7i_CgGU1PMH.iHjEo9vsiT7p0pwJbg_MVavcP9zLSYS3aUwZO.L8y9-fqE8muu8lJVNn" ascii
        $s4 = "UQq75JiR_Lp9Cyl3cLWTX7ovsDThjw6B-y3_Mk-EksNRDLZcrm1-GOql5gOcMpbdbuv6mxEI4f1iW.uIvZDHYm6IfKnDbP11U4l6" ascii
        $s5 = "_53.3nelXfuKj3Y0ZPVjU_EpOUO4TFUzvjPrPVyDo.mNDgN7QTHaCwPEozNZMjWB67HtbsVQXJ7hBrV.9LGmxyNI02o6u8b38TVs" ascii
        $s6 = "y look can pagXpUhM5GteOOhxRHlXP5jhvJDntb3H7-LyC_6-Akn66OWAAMEbBOJQGT9U-VKymNs0fq_tsXrtKjaBLHNYPJdI-" ascii
        $s7 = "9H4kFdubdpfZHfAMy.Oap9uF0IvdfJox7rf6uKBxQIzdgcbMeav7-G8.gtUgTtaD3CU1rD1vScWJS_4TVBblzU3E0WhjV.mJQq3u" ascii
        $s8 = "b1SWgZC83qA4o8oBXJ1nS51UDRH8p.dr7-lA3LP83iV3piXjkr6C4lesQKpGqRK2jbD.HYMrepSbAVuh2oxq7dTR_7Fz9v2rHtcK" ascii
        $s9 = "J4ApZ0rVMBTSwO0XxgYEE1f8_CMnr02KtA9WIEo3Ds3csmjBdE_9KNNn0dPmy8-urnVhAu4svD_Hbj9qsz3QKDmkl1ZRJc-oU3j0" ascii
        $s10 = "GS1Zi8DL-_rCnullXmdXwxSkXSZpYD7Ia1YNlx8Pq9PRbI-9g1iDq.kTIJBpD5qzKV7B76PHU1eAksu4VMRX_LaGcbh50fdwMzwZ" ascii
        $s11 = "8zSaF0j_BwFXMptAd_Vo81atAx04HhQ-BpVoEdGJi5fPO0ZVV6ZM79DmQXFIgj1w-WSCemufruieskafySfKUiudpCkfq5ciC9ub" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1207296 and 12 of them
}

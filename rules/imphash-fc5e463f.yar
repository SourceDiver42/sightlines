rule Sightlines_imphash_fc5e463f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fc5e463f"
        date = "2026-11-10"
        campaign = "imphash-fc5e463f"
        family = ""
        hash = "07605f6067450439191545ff2876f885eb0a76fa876d52be00e39a62e8b4832c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fc5e463f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "EFITI9wHx8sTaxQUq4MLaO3Nu6WjqKYZxfZiy-qyYDuc2NXkdTVLT_K_uonYNrSELsOkNCsfBC0wUK7lmPGte12rci_HBHfAJuzg" ascii
        $s1 = "2q38eIdf_u9eljQgfcEROa66ybnrwa1V8BY-TK5KvB9TYJk6GQck6YcT.yzfcXuM3ARrxmMWhXot0ULdYp9Z_5gPokh1YKwi7CT1" ascii
        $s2 = "iH0__XaC68Qj9K2HevtFDfYnoSyFWN48GGZRcKpUbs-nXIOtxCeZhsq3U5djFEpRLCSyNtw3HKKjuNodE6mABIF1ub58EkFO61Q7" ascii
        $s3 = "S7YtwFmvAcTpQF0JGkXipqeDxV02YqkS8a.SsvPU2wdWF-luoEYMwr40WMqTIBgcKK32U9sGgfDm1bUWGCoo84qRkG5EJJDjrGCN" ascii
        $s4 = "_oR7xwtC9kApI-6Or449YvbeVarJ5LpSVc_nUp_W4cVjuYgmuXTNUHlpzTK9HS0YRj4xhO7HgLrZTQEoHmdNmsn3AVB5Qf012345" ascii
        $s5 = "wu6QCC3G4TlzrbZSeKimgkZ5UxaWH.37YCaThcP1xz2YZTuZVvy3RYUz94-9G4o.qpJ_kD8NFHYr8Y7FOo5UfP2RRxRBpgTvt.Wn" ascii
        $s6 = "J2kiMuAQQBCHawRTFQlMwDuMombhou1wdCxT6YaDK5EiXW7g-9ezbxvDsypd_LTu3qNbhETitdHNSSPPrfcpzWPc4YyX3rmBMPpt" ascii
        $s7 = "2kfqfm6QPPxLx.n57mEMoRY-suCyOgfgnGC5YzPQI3uyiM4.SjayKIm51cAv_aPWEqA22wBWYfJbsf7lK.XdHjrpUR0L57EE6F7B" ascii
        $s8 = "APHtWgFApUdhhThqY.1gJ1BUa0QNSYT_doMFlcF5sLW_g82Iuv6.LIiqqoFUAEcmPOeI9kQ4uMCKxmu0nHoV4.MT2arr8Wo6ljjG" ascii
        $s9 = "nEkm7nZfv.0uYniQXG0dX209yLI6zR9Vf20LLssPH_3.GUf5PgIF7boQkzHL9PhPTem-gDgqzWKaW.CNPcHT824ouls46VZtFtwF" ascii
        $s10 = "7vzPKbce_atid1312WDRoUF5eebr6MUuzxcZyC8PpKWsXmN4O7WEO3LHkp8FQJNYeI6DPTo4VI5th757S7AoN4RA6HjjdIi1_sJ8" ascii
        $s11 = "nAIforXLYogKGNbh-g-4JNuNbYWEas2nZ0bWqcilN52F16hbNkHVxrJfHWhwBUnjezLWiDYtaFZNZKndXTq_aGm7LCicHX8IRSVE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1238016 and 12 of them
}

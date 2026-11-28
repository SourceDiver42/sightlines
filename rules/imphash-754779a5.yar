rule Sightlines_imphash_754779a5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-754779a5"
        date = "2026-11-24"
        campaign = "imphash-754779a5"
        family = ""
        hash = "123e22704c32197dc96a8c6baa806b258ba3486ba5561f8c526019fcd1953893"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-754779a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FEQv16xRceyMq2GTF9zncI1lEKz1WCC0P9HtgcxDaI3N-cjY-bAdBuN4zNiZmxpRX4OXwvdS7CNmivo-60rtxMesMhifAu98VowH" ascii
        $s1 = "e4YSqx-kZY-vuZFdnPzdTppDLjqCzWG2Od5XaP6GTRH1yKtmff4bnTWtA9_puPtAFRZ8oMv3V6Qsw6sDrieDNTmSFBHBjTM5J_x6" ascii
        $s2 = "ZCVkTKhuFJBf0681zyBe-fEsCO9-L20_mRMPewmqLis6d3Xor_zN4H6KbWPDC9lanO3lFHhljwCA89Yc6JpSDLNOhDZ9xspp0xAO" ascii
        $s3 = "uaNCt-60pv4nIsObOwhGRnLkOkm1YQtlxJckVjrLLXfIx87lTKKkfxAfbV9CMzfe24X6PTOEX1Cti9ZWDZJwB6-G8rDyEahFw61S" ascii
        $s4 = "FRdlx9CFps9R2TNZ836CvnVpA-cj6shACIVF_rpLe-1LlHJ_rw9sBdNNhFeEiyGPyfh4u3z4-aNGTTOyzhqxw5AIIEkY0UKooSgz" ascii
        $s5 = "m3LBihVrqm_D_UJ_Y_nOfPsbtcg0fWkjhk4AFxoW9EHU5orH0RyKnab5dFAxkELkeasVzwOoxMq_u9ThJIdRqg3Gp8qre1bv6ujR" ascii
        $s6 = "eBH5aQ3NeD3Q7kFaluBVVyETN4w4WQ-fT787NlVYgyWzcORxcqyTU5YcEoJDlYLUX2qReu6L8bXnsgjxfUJ-hS7zBKswPIp9rjA_" ascii
        $s7 = "KrhK9nW2_vSKaczvlra_qBpQSqRVXvkVCetlGQPuI_51jo4nQ34dfN61jczT849-AqwDtNuy2t3xsCz3-Js5B0h3YYi4miG32Dbr" ascii
        $s8 = "Ptgo_F-aK1iwsxrSnbXingF2Cumi37eYzIGuR1qbxirnhXkrWBXHErLdlIQyPhljFGQpHTHI4Jir5VR8NGvOldGcL0Toqti477ak" ascii
        $s9 = "7jwlaIhia8N0hlYxi50fQqFQybugEFtUrhUdjgBp0oJvrnQpa-CQ94GWV93L31dButvajkgGpdl12yPeq2N4ND6FKaLXmzTrj-si" ascii
        $s10 = "z9xg0oK6rzQJlXNthRq2mFdrGy13Z-7TigMQD_kaSRuAMugEthVoh4Wsp4RuyVqni1OWnHtO9Rr8IQgCjXOland, value highe" ascii
        $s11 = "0Kb-DJ9ZEbLHb2Tk5By-szLVTcUtnusdQsl6AoGw1NvWZGP5dp3OH-GAuZhrlhGUYY1OYjzoEJjIeARumRXrDphgyr1Kalcd4wLB" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1251328 and 12 of them
}

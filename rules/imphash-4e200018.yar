rule Sightlines_imphash_4e200018_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4e200018"
        date = "2026-11-16"
        campaign = "imphash-4e200018"
        family = ""
        hash = "347a059d0f81f9322812d01abc95fd42625c9aff70bc037853a528c5a36016ee"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4e200018.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nnot have dynamic sizewpS_V4yAmwUl3Wx1NfCwjjXNMxHbnLvKk5FDuIicnbRKWT0GMAAZFworh1cLeVcWZPJaz-R76qcjzY" ascii
        $s1 = "dOv2PYjqtd3-cW2VpNiCQLqKcCuJHY_X45qMEIaL9IIC1e4MC35QrN-Sjlkp_B8V1-TyNghi9hFjxobbatDRzlvyHjuDYx6E_3Tm" ascii
        $s2 = "uBh9kK08MXNxzUAozLiusItv5P3rHWYM7mbx3J1M2RVQ9OYrPlY3GHLKeOFZY0aYI4Dh6ldz5UjQVpZWw709etZNJfh-6c16zKRB" ascii
        $s3 = "Cy6C_Teiy5sx4bZUMj3CCxs7SjipyIkBi3RG-uV0GndJdKwSTBUf4NNvTn0ZgME8lKFB1aMiK-hI9iOt2IVGkmJxBDPrdR3H7o2W" ascii
        $s4 = "Tt_ucdQ3xwe82akXjKYuVdoMBdgfjiPcO-WS2PLsrlbqcqtIA3vbCNqsGq0mvrgyAOavJf-0rNFzGRXDc6JGU9FRsv2cvj4081WD" ascii
        $s5 = "2VnrDMs2jW5w1uCqOJOso--R5AV_rJU8y8sLf2tpvNnffSJ_9gpf3Talzj-Al6ceCwiTNS5cRHZZCkx9UyEw10twUQ4jFvQ-ThM7" ascii
        $s6 = "6i-ApG2EXLdtcYBy6E58wtz_NYoosl9FjAJ4CvI--h6nQft4UufHpg7BjsnwM9gcwkY0dxmZLlel-f_rDGo1au8sElemTvkviUhY" ascii
        $s7 = "dKAVlmutxrlPRg4CxNF56aZzZZMfaTQJOGZ2Nsz0eP0w30BC1nVjlKAFKujGUZdx1U1i0X_9q_Xfq5yEcQ8_pnexbDvn-dcOaj7U" ascii
        $s8 = "ZKA6QMGdTOJ7Ir9TI2Do3OYlUdHDp7bGBEyY4GvatMm_wYCyRRXSh3dww-HqC2ah5SzoKvoeYlzUl_Z8-puB_E5FV9rfQTSnNJXz" ascii
        $s9 = "Z5zjosz_ZPS2p7V_hUwqCVafSJAytSlMKnIFRmMSF85sDzU-_Q3CK9LmSnD-6rT0UM2AObAepOs7LkugZXA88aIXhiILJptWdBQj" ascii
        $s10 = "dkyLLQ0u7E8mLbrcbEvKnSIbwO6P2glLjBpb8kZe_RHNE-n7PUEzhXW9qQvu4QRp3hRxz-SfdM5vTzFUXCLRTCDataChannel ca" ascii
        $s11 = "0qX_-xawachmXYoztm124EsZT8RzMD-aTQd-9I6Op-L5yqB7RdHSDnxfNfkUHcbMNcKKpdjRvBu4lI-O7Jjp_-HK_EXBwke1vGqt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1192960 and 12 of them
}

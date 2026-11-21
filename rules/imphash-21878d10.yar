rule Sightlines_imphash_21878d10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-21878d10"
        date = "2026-11-11"
        campaign = "imphash-21878d10"
        family = ""
        hash = "700f8eb2f257a7bf04013d922b57093ba208f712854a907f5cc0f3aafc327fdb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-21878d10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "c1Z-Fv7u3ji1044tsl8A-UHJ8nK8O9RipbTG8EOQ-9cfzyeAb24mhvzT-DzCk1tVaMM73JSWdeIc3LulDSHB4UVsGYXC-sPKr_Vv" ascii
        $s1 = "2zJMEVzy0NGy-d0WvQlHVl47uuwDh9rW1XW0Wv49AQL_SfIF-TqLOR3JJiZ5oojq1gd7GviOeC176rkhPC-3-2ZZ9883nV6YKOpo" ascii
        $s2 = "Itjv-EgJFizwK6nfB18xluxNcHyup44Vl202UPB276EwJnGFaWoNaG2epfzT5wSDAZ-KLwDdm1MFTpZ5n8QpuIyZ9Cq4upkO4PzY" ascii
        $s3 = "7dC7-pg28BH4E-s9Q7Z1j4_CpZW09eKsF0cgVw3L-EropP_mH2YB6YTNKIwDuSbNw_Uw1zZBYnH6-Sk9JZXyqQjPFMAhmp5szn_i" ascii
        $s4 = "3vJqEWQMuRH_B8pBq0xMhdDaEPVqoGGJDnxMUL9UwJt2Y4jzUn3TVHMwVXsgo8O0C6uHzTnXJaLaS2bs-ACxQdBf4PDZiO5vvyk6" ascii
        $s5 = "s8hAWRX3KcfvB_Lzr2cDyV6JhOcCKxQyTqYvFQkjO_M2ExE9ZFtuNpnCA_lGSXFNlp3m_ydrCconPj9zQIFhiqdE_NA0HxBq48cU" ascii
        $s6 = "dPftNsocGyYo2U-JOMip56fHUd61pNs9Oi_rDpL-eYD8-lY_eEwBabaWhgkgj9-dX3mdnyT-vM4LHOuqvxmAzBBNOb5qXB4ABRGD" ascii
        $s7 = "8SJASh1fDbeDcWIzYINOExxljIbRv_csFE9Ihdnbc-ADpgL7iq6T1oeBrAxYwTVIFGqXy3yFuHdKu65IdwNK2No9v9z5Rk4NXu-3" ascii
        $s8 = "NI-s8PUFumB8mdAj9Qs4pRStWLxkBRkTd-YQAZvQXUZVsC4NWsuiOfl34RwoEp7efiNlcDePTXH_FVugfGrKjV3MWIwY37M9po2F" ascii
        $s9 = "OLL1ifJTIOF7TIY8Pk2U0W1WUCNJQvkqpW2OdZMoF0ogTBMVufRehlpP4i8x1Wn0K0KPBosLjy-KbxUGEz99QSeKAZtaYpxtprC8" ascii
        $s10 = "gVyHxmYmy3taXjOen69fWBpF9in_KoMKrfGdsfv09EiEqLUbzd3Ir8UGna05YN4pZzOHRvcFGrXpSUcnB5hg19XfuRmdkWVz0lxS" ascii
        $s11 = "6wSGqs6EI6QLZgdxeQBa9BzWU8cN_EIVtWRZUdk26pgMhPXIxp6rEpKpytGovA--wkvqzviYnzWSnDFaRmI9bSl1MfrZ8uoSQJwL" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1180672 and 12 of them
}

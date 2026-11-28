rule Sightlines_imphash_2aab0899_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2aab0899"
        date = "2026-11-20"
        campaign = "imphash-2aab0899"
        family = ""
        hash = "168c3225dbb460a75f58d19186686738a4710eb270343e8898420b8c5e3c364d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2aab0899.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "YMowsrOp9ay2jbGIH0FuNp8sprA24n1agOjHv3ji7vfD4K4FmUY26ml2sGxGEnQiWpTkVqwGfd5Jc_YH4bCRrRJYpev0hSZch9PQ" ascii
        $s1 = "EFlJgFUU97yvO8mf8iyRdAP8cqGsmwjmz94vQZT1kn5aKchRileoWn_WN7pBeluZRHlgS-8RxxWKED2VtJSBN_q181cuyyLbmPxI" ascii
        $s2 = "bmFOfLiI84BXnOd3QUCT7LRvni24TfIP-tRmOxOVYWQXx0lFncNTGjKSRsCN3AZwvXWzegqa_h1htD0bv4YZZrUv1qgNhz6SekU1" ascii
        $s3 = "AftJ6-6nRqf_Rk87KLFUPfbbg8v1EJuJ860wnQ9YfSMdxP5leKhxLS7I0m9Oda7GIuA6RrVsK7ooE7auXXA1ccPkyWN4GHwQxO3B" ascii
        $s4 = "2vyFTcT_IlBWuKx8hPaBY1CVL9xQbkLs9f_mGzVqT5FFDhVIFWMLbQ56i38So46jHRlOSgl2xErZOb9bPTDqTZgUESNQp3gU_ee-" ascii
        $s5 = "MHOg-ndD2w4odPYO8AOPocBofzxSB_eIbNs8rDdHv7WASWok_pjkYg-uHs6F1QXRENeJ4UwgZmSsTbUI_8RFa1-j1wxyBh5kLK4f" ascii
        $s6 = "pMI5-RoeKRQ9nNvmRUmx1VAyexWFqgtSfHWPgWTzk0QB4s6QwYlEBbN78r2DVBB0cEcB_Zas9P__pZ1I16fXHabfdQzX_AKgNVeS" ascii
        $s7 = "q8mHJLVNyAtrX1c_uR1o2ExIh2oPC6UvEH4-sDlTxdR2FsUFUFELpVl-Az7txsmHT9KmIq0A7KPgxhtQMrcZnqZWbPRaAgwc5lfX" ascii
        $s8 = "5beDEtZKGISPVKo15X7dLWQeicsP9WwvaTwf3pBcuHTAi44VnJUMdFkSsgudr9jH7NDlQFRXNu9dwjfjEUZbZi4SREm2jgG8wW1x" ascii
        $s9 = "at3tvv4OS51m3695jLi3aWZ1u7yQ7RyAD4rCFVIhnqQHKM7E6s4rhnPrApPHycJsqnDxKKi6fAWSlXopEMYxrNC5gPe-nHnc0G8P" ascii
        $s10 = "bZCuyJ-uqJ6sX_IaFnip22fEjL_xNoBo7xMJYehklchNu8p7IKloIDW0cmd8BfMLOOqAPzwRCOHpYSxI_XDo3sATfzq2xvnuAiN4" ascii
        $s11 = "6HV1TwqaNMKW5ACZ_30GVrUOZbShGeh8gHrq5DaqpI6rMUdtmmoiR7pXyTxI83zMft76nuzTTFlAkuMMNLR9EF4787RigWW2RLHN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1258496 and 12 of them
}

rule Sightlines_imphash_9bd0241c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9bd0241c"
        date = "2026-11-13"
        campaign = "imphash-9bd0241c"
        family = ""
        hash = "29093fbb58c305b8da56e21f040ab90743e0e34049e8746e297803bb4e6b8095"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9bd0241c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ble adding14w1d79dme9035ye47v2bllfsqnbypuum4kqucmea5_a68.1hylnoyo5seyx6t1hodz2s1px7ozh1v1qf0s755lztk" ascii
        $s1 = " %gMB6dtco1w10ebqhz21zh9f7ldxv3dob4k1dm1lohnn7etgwonnmp7kxpyoy3t5pua45q6n9eya6721must as way at chan" ascii
        $s2 = "ingle predicated storehnuoex3z4xf42u4gf75f4lkv!!!VARRAY CORRUPTED: logical size greater than allowed" ascii
        $s3 = "@?>F91pawxo29hkkaay2bchkxqxl0e66bbwln4dtm3dksadmvvq6fslud0tpkcay7yoop1oxaxl6fz5ywvm9pgeokgmzkont2ho3" ascii
        $s4 = "Scbsxogbl2dczba56shkm3wds--zero-fill-buffers command line option9p3lysue9kyobmlcy252y57g1z4ac2voh7w4" ascii
        $s5 = "bwdxswdntnbkq3kue9lanzmt66110npmttdkglsudtyk5sho2us5ahCorsURLLoaderFactory: same-origin credentials " ascii
        $s6 = "Offer failed because DTLS identity request Android2wpl2afgaq1sy42zhcnb33s6bl9hdumz21023vbu" ascii
        $s7 = "e2zm0nfhp4t11_mmpodyzox3xhe0m3xc5ft9zfwyw9nuq3qhblsa2amp_p4dsfqekkukkv61b5qccsglcv6gyu3wbcb5supfpuo_" ascii
        $s8 = "?vk2vap9shul2mf2mlmm5zs112pktbdllky260sofsuhpf6ste4t075qvnyd407wset turn change three back give look" ascii
        $s9 = "f7d75x91vqnwvd1c70fsywka1qeov0bbzqxwblxkll5hdvdo6tqoak462p7u9a5ecueh6zngslnsva5d2t9q3nvvsmu_tce4no0e" ascii
        $s10 = "2ek55tm26xn7d4s2b13p4v9gt5qecad1swu3nl6z0mzaoen1u5zzgdwfcfmkto46zq6nl4qlk7g5m0e601hmh6lyk9nq41Create" ascii
        $s11 = "file from local candidatek0aeqha5d91v6tbhsxn2dy15nlosb63ftbqq4vy45zh07s3ua0kashl0h2n1byqvbnm5ugmdkm7" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1230848 and 12 of them
}

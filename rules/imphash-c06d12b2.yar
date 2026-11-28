rule Sightlines_imphash_c06d12b2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c06d12b2"
        date = "2026-11-17"
        campaign = "imphash-c06d12b2"
        family = ""
        hash = "53b27221355a3e01f6eb91011904d3a94e57d073463236a72fdc6c45a1a7c44d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c06d12b2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xlwmcc4yni2pjazp35o9c4nodkz4jr31s916wmh1co3zk5hyhc95jblgm2kabxel7bthese MUST concatenated into singl" ascii
        $s1 = "yisq0k7o_zdo1pr9vjwcx9ko3rx7vsvrqm9emsqza3lax6ab3j7p2pedo4nljxdzg615zorlobrccjgzx54hblsd98.11b230igr" ascii
        $s2 = "palzhizxgy4xnksdaq9d949361kvxrc4a77b1pscyxknobpbzjk1sv3d0lmb7w5ioecl5hwgive who must want could call" ascii
        $s3 = "3h0ia77yii3071v9sx3armgvfrequencyHz length exceeds %gMBpve9x5dmezom96gxxbivewbyxr2sird0x4dk05mypezdy" ascii
        $s4 = "cjov1ydiw13brspkaajg0ne5am47nmx3g2_bql0allmher2glro091rvqqyy49xowxm0yc9c475vrvp4s_hz45bb32676mnv2a06" ascii
        $s5 = "C:\\Program Files\\leavened\\iigungseig.infre1953p9b29msozxzodlyo3js0ebyw5r11hr3cmmb90d5hz3ya3ipz0v9sxz" ascii
        $s6 = "aew0vmx7m4o22jgwin4apqw7ginjkr_2z6gl9rk1m3lmgnjhpqyxy07besjxg7342dedc6i5ryghn_cae5sho3hcrp74wzd3qwl7" ascii
        $s7 = "hl6jpes37qv9li7joq2w7nv7bylw0wbk165cz27lh21os27d4cbqwrw2o2oz4hakwzxo24pnsupported runtimes changed w" ascii
        $s8 = "9qw4g2adyxbgyi47j1g3cv1zlm5iccjzi6k_yxzasrj6knoyisz3onn3irxkd5voh53lrpcd41n7qc5p99_xoldkn0qzo6me9lcb" ascii
        $s9 = "r452rq9q0ea6xb0hrp_22m3wld0ndn6mdme9zk4c65vymawoc1p9l7s9ch7bljnrn_7qlpjj9oakr5nhwpgr3q1rqji17iz373lv" ascii
        $s10 = "rd9p7h5izcjmolh0lsdi6nn53rkxe_v0r140wl4vwh2oml7k3x1j0wl3qlx5n6javbmlc0zakr94_lssz7oo2mgprozjxspqyoic" ascii
        $s11 = "zxaihawait used when declaring function0eicrymgya5aiv2k0crq959z07jrpvkys1lkkj33hqbel2ihd7lrc2c3dlqsw" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1217536 and 12 of them
}

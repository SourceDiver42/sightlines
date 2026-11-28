rule Sightlines_tlsh_bc392566_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc392566"
        date = "2026-11-17"
        campaign = "tlsh-bc392566"
        family = "wardenstealer"
        hash = "1b508ac35c5ab75c1c4b2a0593fd48462de9add8ede53328363eb7ccd84a3383"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc392566.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "jkmds0eain1cbc_6jlsxxpazcqyk29g7hq53gvn9w00a53394rbs4jo74ea2b_dissvbhz2onkywg9xeg6yq6ddlvmm09ll1e4m5" ascii
        $s1 = "pvnds0axpza6d0lhnoinezxpcw6_z77nbaq69d1wlo4cybcjl1rcrhz4q6eai2yjvv34jqekk2_03mmdevgh9sp327imw113c5yz" ascii
        $s2 = "l05chjdrj794dly_m0nzcobyxxjhe3y5mrbyr5xh3jkl6vr6s2wkajxi1vo1n6_42wim7zl9gpqavbinx91dnsg6hb3gqlpmwqcq" ascii
        $s3 = "kcs6_rbxx9eex35lnzaj47k4ei35zlc3k4bqnzwd40ov10py1pm_h2z67li3ld99xvvyax7ddwage26g0ji27a26pqhcrop0x6_s" ascii
        $s4 = "71czddia5vmwd9zbes0emn11mh5jbkq4nakhx_2acriz2465aopr5e4qsy3nv7d6lheqgra3ljv3wgrkxzmi_md7y5c996012rlh" ascii
        $s5 = "sxqnxcrawi2k_jjxiw1dpv5gi309kz6mxngeb1bmvjg7a6ypo00k4h3xqc4_6wn2qw223jlk5a127m5byhdridyqzghso7wegjc6" ascii
        $s6 = "3zxmb74hdkyi_rzwbpyzkjzdmnoalxliq5waolqbma0pjp1n1v2veay16qe_x792je65s43zgo9raanhkqxzr4kh5iggskcsho6e" ascii
        $s7 = "xgd65izhxxowh4g6rzo1z2qbaz_y3icmng9oyx75vr5ecsq0g6c7je9174plp9jja4jyj0vsc_xgw32bnl2wr6l301rxdv4vsrke" ascii
        $s8 = "am70mb_x5j6k65gzxg4jaowphhwz0ilcqo1k2ge5q2hknqc9s770i_a1gyb4925sr4d4d03vr90d6bsd7nx5i4pazeyja9orq3xx" ascii
        $s9 = "bcgq1i2haldp230_h6vrn6d9evr2ly5eq4q3imc1ozolrexlbj6ej6ap4iw910_334sv9ambz5wxpks0v4g7awmkvyrek7abrkv1" ascii
        $s10 = "95lxdqgh6plsc7a2p71m3ekxppaq_m160qwglrmz1o975eh9xrhiwbbzw2h7my734rdci2avmjl_4n69ak3kwv3isy2x3jsrhjng" ascii
        $s11 = "6bl6xb7yhdj6ez4z46_5i6294p23krjegm4mkcqihy3qlczyd16ncwwh07vgxsim9_y15x097y17a1ieywqowclvgknwlwasv3op" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1589248 and 12 of them
}

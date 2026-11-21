rule Sightlines_imphash_78d5b833_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-78d5b833"
        date = "2026-11-16"
        campaign = "imphash-78d5b833"
        family = ""
        hash = "05e075ac5438d9f2ba415986f9c473590ffd867eb0c098c052c5b0a08c514dee"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-78d5b833.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "jun3c63m3shhgu6yaj8as2186amx5zf63_6qpause request from vault with historygfsyq2aaxc1x6dk84g5lxzw1rb0" ascii
        $s1 = "_o2gz57w77bl5dzdhnk1mld5sggjsqhwseldt0s6h1d73xk7b8xucrug3rc0fstggfkko2xam30lf4ske45l70rjuqt8y46but m" ascii
        $s2 = "?dyaz306rgl3xm20qe8fdszksyj5n6zkraq8qjk7zqw6lxwdsx3jfu_bguels01show at first day know could can kind" ascii
        $s3 = "ktghrwqecfn3u1aas_f1rz2c8bnl14moao05jl6hhr6y3totd0_e25bu62mc3zw558naojyg0oc7faydegk_rct8m505lofxb1wy" ascii
        $s4 = "dd5ac3tcq86y1tw8qatctb5e5r8k_m8e7nx8dfg0mxknk6h4qykh62nzlzln2_0jlb0aq0dw6o2k6sg16jsg5crbaf1rum_hr1as" ascii
        $s5 = "ncn0d00ablfz1chrc50xlzbwlczy7u84kr4qzduy881bag5tdawsesmq74y1h4y3sf60n3txrfs7ocfj4qx23o2oo_xzynm2la1m" ascii
        $s6 = "mw44zmh0skj4zc1qq6c5r8n5xfgfaa4e1btr6kmh7mejjgtr_3ohbuhl7xh77r5tm8w45ky43uo0qzkdfueo7r5qqj56buqplan " ascii
        $s7 = "c_w2657ggtb1tq864than6q4a0zl3d7s8l_o5220ffl3nrdjw7q6y4zylms70ufaq05_kzckkr3mu2fc8natu8be2sg56gmztgj1" ascii
        $s8 = "f8rzfotr4x7y3mnsexq5eolw2w2a0kctbwc2l437lcny481d8a44rqmtc0w73xkl_41bu2gnh5mgewj4aqhf5bx17mdxrs0zk_r3" ascii
        $s9 = "cta1rshettc8j0ojf0_5w0zodqz2yjwfl2cmh34tnghh2dkamoj_e1e142kx2fx0yk4x4nhsfkklfeucyqla_6bn51g66u88a4dx" ascii
        $s10 = "f7r8smcyl5ndxe6w2gw4dno814rjlygf55yy0k5kodrcjfebb3qsa3hjs78407_y8rwbckaetdu7sz01sa0e5bmhu41sstb_5bqk" ascii
        $s11 = "rotarjmfjk5m40e6un5ab5ye56jc4g0ooqd86hrg315onyx70g_q2q3cnd5l4wlzud52h2xo2ktn2q1zcbas" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1193984 and 12 of them
}

rule Sightlines_tlsh_b5aa1387_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5aa1387"
        date = "2026-11-17"
        campaign = "tlsh-b5aa1387"
        family = "wardenstealer"
        hash = "461e210c841c85565ab95ed4300da190679c23efc9dbafed9084e4a4ee4f05b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5aa1387.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "c6acfj30hnzu4j-2gee7fmauh0i8p27dg94t7zz6x9o71d2ud1l-bipl56bnkocq64lqe3xxkekhms2bfi6n9g1j-p3q6kdt45to" ascii
        $s1 = "50jf9imiaptlgbgno-sq8o31usc0zn4tz8a8x3fxt4eampj9ch494j-8k3qd0ecnxhz7zteuh21ijb11cek66jk5m63-pkdq578f" ascii
        $s2 = "2t5cagk4pmpu2zb5opm746hnao8na43x-i9ujk75dz3o9hfepil1z3024bm8pget6qggl-djq4j4jix0bul1jqd8asszoudchtfs" ascii
        $s3 = "lgz8subxa4n72kja-c9cqmbf5tdxhp6x4mltpo07jtc6tsd4dif33-8mloa1605652gp98siz2ee0067bou8gedo9x-2htpjkkcn" ascii
        $s4 = "lmgp-4a7zh90cx48oq0qxhugjgdn241n356mfo7hz-2ailx9og36iathimefudksiii5t348ojjsb1-ndzqx5zmkukbcslf021cx" ascii
        $s5 = "fofk0tqqjehl25xj8dk7lnt8xqs-udelazl1pnii351chn3xa2cg3786sc1egb0u-usmtoujqbk47qlps5med99h397x562fzsgx" ascii
        $s6 = "ajqbn9h92j5oq5u-e411ftaznmtoduo1hxkdd3scq68alleqku49-xjuhn45917nxbgeuh6bxakg8m61302ff8zps-7p8it0o7tg" ascii
        $s7 = "242hl9qgzdkpc9qz1iuu2kn5-dlta803f78mk8ciejjsg7gh5il3z0kmdxe3m-oh6hqp6qx4nsc4fabbgld05nz3d7pm18456b-0" ascii
        $s8 = "b8put51ebjcqok7unekqgzsafe3do-ga6cne52id9jmnzxfuzgk6max4nn260asdxp-ljg6f5c0eupd84bhb013b7mhsjt73it16" ascii
        $s9 = "z3xfdpc4a5fdae7f-4dljzthqcml9shofp250fhnjk0n3ni642iux-fokjzn7jbt75t6hb099928akzzqgpent8esm-16bx8xiue" ascii
        $s10 = "zedmkao-dn53jt09b1gtop2xcduf0pl1jt47bhoeff21-eb81u6s77h5q2mkmzj4fpl5m6ljm8isla8k3-l6ha0078enhux9bstg" ascii
        $s11 = "4gl-uznbxfqt9qjjee4kh0pk3ek9tlzstdadbox3-lk3g69jd36xzn5jiop42dt250i24cx778itp-s10c2u6mxs8h1pgo5md05o" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1515520 and 12 of them
}

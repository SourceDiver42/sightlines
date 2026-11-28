rule Sightlines_imphash_f456262e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f456262e"
        date = "2026-11-14"
        campaign = "imphash-f456262e"
        family = ""
        hash = "0166953e895105891b7553859e8d1f53c4c94cf5ad2c46262fdb1232a9ecb201"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f456262e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1a7uyu8mxkmacro defined with WebIDL4broqk0up2iu7s27xosmaa7ssp5jru8pc1rshyzn3jzjfo7qqg46mz9yn722l5rga" ascii
        $s1 = "ob9oih8bju7Legacy GetStats called with nextTick avoid follow-upj1inquqsl3xg7y6hgf4ksm7v3rrqarv" ascii
        $s2 = "ed Int32 without loss precisionvfqmk786v540y2mzlu7p6x7mbm98kxio6hm52bafr6nzxv9zlnl4l2hphqbbayv3bv3jl" ascii
        $s3 = "456789ABCDEFzhsca3bcuhblc6iyv64p1r4cvvn3nk4xbv75j1vrir.rh86uj6rfubcipsambkiz2735k9200cuqa8o5u19rnx6m" ascii
        $s4 = "@?>Fx1jgk24x0za8ub2vi50im7vzrajpfsl24n7oh8bgmr36uyplj5vz2n6n4k9a6rjlnyz7pbr520qxhqanyvlnp31skuhxrxi8" ascii
        $s5 = "ve-C methods, Objective-C properties, parameters9aya5qua131bpz24j5b56fjoi1kzf9mab0i7hukz2is72lo5rv64" ascii
        $s6 = "x64hybckb8ofjjvyr7b25p5b8j0nrInserts node into self descendant5yyrrz99x40kqvygbliuuap9hzo034vconfig " ascii
        $s7 = "Non-finite value found wrong type016zk710nnvqxjfz4047kj6jqpnn15i4gffkhx78hui2qa1m8va8si3u68kolizhjip" ascii
        $s8 = "kh8jvqk1mrohil6gv1gC:\\ProgramData\\innovatively\\ooppeonsjhviabpn3hr9b3k44iuv1p7cz4ygv7q33ugjfsbum35fv" ascii
        $s9 = "passed command line optionyulgpch6bf7s7o6usiamz14x46xcu21pvb7s2863vs.aipr3n3zc5almvqi7nh74ljc6yj358r" ascii
        $s10 = "ov401y7svag0u1ny1qr2ks7izb747xmrn.9z2qrpxpzhcy076lcgb9chxqzfjfyrr7xksph1vrj3jhpoint their the any go" ascii
        $s11 = "mn186crkaxus0puo46v0aozcoq4r2b53u1hfgph7put know as very need are show so diffebfcrs6qb7liv6kvom5rkj" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1234944 and 12 of them
}

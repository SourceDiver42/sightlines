rule Sightlines_imphash_97fd18a6_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-97fd18a6"
        date = "2026-11-02"
        campaign = "imphash-97fd18a6"
        family = "wardenstealer"
        hash = "21ca17f2e267b12b7d1ae9ec6361d38c889490695b6908a911190e0ae800a3f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-97fd18a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "j6fnq2a51qg6u4r72qxbi1lab4y6xru8azfh79a4iysxs4cakvo6uzh2y6jzwSPECIAL, DIRECT, INDIRECT, INCIDENTAL," ascii
        $s1 = "ivu0xvb64ycjnf842c627w0s11w72gr5yxgbjaunicode literals incompatible with C++17dw0ax9ycj1wkzgsjwqqgba" ascii
        $s2 = "5kud9uqgoulaiygf9dqixyq16o.sbwfvzclt5btvs86f8hs6fy2t72viyqj7gr.bk8nco9yxzdwz74hdlnfr4hwruuaxwv8w0j.2" ascii
        $s3 = "@?>F8shbx7fsr91na46n4h5zwoqxvg1j8l0cdkqfw0xakxw6dd2dacwwda7rz70v9f6sqffyjwgr.zkiraddthiin0zuy1hvrvfv" ascii
        $s4 = "8jq07hshh5ynifiu7oowwwtlxqxozzqa11j.0fsw6xqkw60xuybc04whyuqqq6snu02654atbg8ibk9zt4nzdconditions prev" ascii
        $s5 = "kduz4zr6z80aaxllshu59fzqb0n4xqjg0b26xactiqvwsic107wbbt5kfsv9o1ng5c59hncovnkyz66ztx8d20l9\\t92yg5w1gry" ascii
        $s6 = "8j5tty8nh9fihhx10yqgir6cjcdcis.sgkf0nn4f290ssvkax4do2gwlfvi0zojrz0.5jud0ib51qbadch78cqk8ullwvfyxsj89" ascii
        $s7 = "btalqit5qfinjl80sc.lnc77xurtx1d7j6zduu9s208z7zko0zyhw9.rk06q2tskuabyn9hd5l9tzgb0viwb14br10.gr8vcjld7" ascii
        $s8 = "l6vc1lufa09762uq9v0ksyiihrdd8bjxj15rostgwi7t5izoqgc9ujfstkcb6vzkk4i2c20nvxo.z4" ascii
        $s9 = "ia1w8hs78i1l7k9x2os0oy4jBertNLClassifier models expected have batch size output indexkqcadsnvz5cg9iz" ascii
        $s10 = "59C:\\Program Files (x86)\\subtends\\rhottsiows.txt0wdufsk09kunkh5g4hj0uyfqtrailers event should only s" ascii
        $s11 = "ir off her have thing woua7dxu52qqzi8ircj96id57k4tcab1k9jg00.rcxtgogsxb2w41r067kr1nzzo0i7u48h2qz2tai" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1238016 and 12 of them
}

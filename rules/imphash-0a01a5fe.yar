rule Sightlines_imphash_0a01a5fe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0a01a5fe"
        date = "2026-11-10"
        campaign = "imphash-0a01a5fe"
        family = ""
        hash = "0ac367fe893f83a08600d1c44f4bb20421bed37a629ed76856f8fbbd58f32d81"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0a01a5fe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "g2prp47tqtrhsbxrzz0vtpmd1czbzqaf3gavzrdbf1x6v5l7pjvih24a69mf52tcamqcmv16hzfx5pyykkHandling STARTUP r" ascii
        $s1 = "hrq2sd2hafzqzdxi14mikbqq13taq18v72237im8pys6ayx.kx54zjh79c3lyp0bk3uquf6tq08lpmost my on work home be" ascii
        $s2 = "croSD readerk65xfqv3u60rxddcx2fd2sjisijd13gd371f66yb6042alqfgpyl7bvv5hyd73gz8tkg9y4h02az75k170ypmkxy" ascii
        $s3 = "ch0jqxbj875xxzhbd62am883qgv7xgucb9jr0ddfm47up3syjt1yqyrk2qdhlay79ydkf8pd42gc9xjt3bbp-fexperimental-o" ascii
        $s4 = "am8i4dextlang cannot used togetherss732hhk23sf9u8g3gv1mhzv1zrqisvz4hjfpz05kqg6ahlj6vqrvl87py8d0thhrl" ascii
        $s5 = "azhk7maus0btld723kxz0vis976rc4dbhqadno like and most were just mzq7xz36mygtda02y1qm88i0kgbmr6r9150bt" ascii
        $s6 = "2xx5is94g2a36k4kpvq9ht3c1ft63lqgqsmd041010xirhyqum0ztbgr7d7form but which such by did give some soun" ascii
        $s7 = "l84ubp1r1kftzc1lrdy2j7zqkku2rbkx599vijkcbthbyp3y4qxhs6.40daf6hq8rblf25z0rlytlg1y2x5b75zam0l.mdestroy" ascii
        $s8 = "n call come time went my made do no no mother its pd91h3vj55x6xj70kkduc82mqhzlfa77b.kC:\\ProgramData\\" ascii
        $s9 = "47agluggmvph0i6.m8jbh8x2i29qzl4lb6xhty61hcuic1kkj.1yx7bi2bqz4syqr5vkrqrah1afkrpb093.91szlf2tssd9i8v9" ascii
        $s10 = "5yu8djpukaxcuisx5.lq6r3qyp9jkq6dqi546kxaivthga0itg942ds3l6z46kz7b3aac4.mRthp2vk20pq8zjm5clddd4q1fy87" ascii
        $s11 = "y.3lxaxzyz3t4rc24pc3h6iu5jrjvjs2k10.uxad0g9bqldqspttq2jfkzlq71j68lmx4.fj8fz2zrz7mzrmvpcagbt9rc86khyg" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1231872 and 12 of them
}

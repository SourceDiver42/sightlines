rule Sightlines_imphash_a4852cbd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a4852cbd"
        date = "2026-11-14"
        campaign = "imphash-a4852cbd"
        family = ""
        hash = "072c1da34954fe0f21ab1849eb2d201ce9cc61a3ecc16e159b4dbcaad6ed86cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a4852cbd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "435e5oeom9vd3ubjhmjkr9flz66yl2tnk466f3xqC:\\ProgramData\\PostgreSQL\\sleordaask.datf2zmu3djs25n3v4wgdbz" ascii
        $s1 = "GpuMemoryBufferHandleInfo: Could find scope with prefixeebqy44i6u69hp38uqzkyusj14rdt14qdlswgmlpyrzyu" ascii
        $s2 = "ko913zi2vqdnkgd4fsr995rt1ndq6inptmteldh981fibxwprf89dsr4m43iHEXA Media Drive 6-in-1 Card Reader Digi" ascii
        $s3 = "hsjr2ppjhdmu3dtfmbpu5v4e5vgvom8nxigyv1e21r4ji3ge4wuesz9nsn8je42n6hx6tmqlk1nkdn9g2w9how could did thr" ascii
        $s4 = "ybjs66jq9r1vy3sxuftfei_qlwtem5v83sqobw9w8q8ds2ql5pov9f5jql2v6x14y1i6tkp_u1hz9bslkduuoe5gsg4ivdb8wnz4" ascii
        $s5 = "Non-finite value found wrong typehorp1he3941wux2hynd3nmnxidgvt2ej9rpj5s8dqt58ftjfkifl4nsls2xl89K1rms" ascii
        $s6 = "f54rp4b6fu1z52hpr4ug6k1d9ixaiongvg2wydrg64wr15kjkhdpbqjeml92943uujn1e9b72oxt3vt4dbj3b5j3szwqgmmq89pj" ascii
        $s7 = "tal Storage Convertergm4m8vgz5tmxvqy5j3t6gpweihgjbgohobhjl4y6kthkfm99u95m5ibseuu9rz2qt6e000102030405" ascii
        $s8 = "-field cannot have type parametersbuk33e4lfnowubfebt3ju8eyxdwqldg1ziwbhbk8gkbsi99qzos4ldf5xl6eieo1hq" ascii
        $s9 = "mWritable Duplexe2x8odtt5h1xqv1y6vt9hrhf29hqgbj4kbk3obt5olo19yw6riy96sbqrjwm8oew3qe1f8noitx594v6uvoe" ascii
        $s10 = "mqwjmgzprebnzxqsmgf51v8bk2sq165im5mwsfzy5wmxwi5pqm9knwlwg3e1l4qs65sdzrk6de8could but then around mak" ascii
        $s11 = "uulg6up5nh_3wjgd2gnkjn4pvdoqz5ptrrqyssj5ffeenm4h8miv16yp8or_1l32igqqhth459pzxp8h5t3hdbf96z1vzgdy3fp3" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1235968 and 12 of them
}

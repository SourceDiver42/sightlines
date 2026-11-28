rule Sightlines_imphash_d598c6cc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d598c6cc"
        date = "2026-11-15"
        campaign = "imphash-d598c6cc"
        family = ""
        hash = "05bd8e54ac18834c7ed3e7e61b04848046c21ec01e11480115a65ca245b785d7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d598c6cc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "g96pxa8mlh9djgkkhpndlpmsuy08wu4gvjrf700f85m9uhsc37zyr885omtjqltpType ExpectedValue operand OpExpectK" ascii
        $s1 = "wvmwah183z3uowjjssgjzxcxp0g6ywjfn-k..3wvh9qxnyl8zrkdy1p8sgpxo3zq6writable side stream, only initiato" ascii
        $s2 = "HR does match format field74jp5o3urrzgcv0gk8xoyj7hdtfvqf6saxkdh365w5kmyv3tj1a7u1f9ckwvzlmrzrfsufm7gy" ascii
        $s3 = "pqyfynjdr1mrw5x1z5o-1u48rqjphfu0qquqcvtzcat7jajvk3s6c4uxc8ar7amtgxu9zxaql0Schannel does support peri" ascii
        $s4 = "ou41r6vqzdzxdy5yvt9n0qqd67kw4toxuhsdnpy-ffny8vwztr6briaoctseiagozxxqajtlgwzmukp7u14cy30kyclz8c76k9vu" ascii
        $s5 = "ecause implicitly deleted hereadgsnd9049hsrlputx7yo16q8lnmxf9woxohu4mvoavo0kytjfxg0nqyt-1cfqw6zxjj4p" ascii
        $s6 = "56789ABCDEF0omzx0pqwgmqzkgrpl05yaujjgcvghm3yqgwngcqw6gwlc6of live even can use then the out because " ascii
        $s7 = "tws7tgsa0vfnmC:\\ProgramData\\cone\\plonnaotz.pdfyo8q88wwsa8jlcfpfug55cgkgzf67u6y96oksmuxkx93qpg45pon8o" ascii
        $s8 = "gpx4pud3w6x9msdesignated initializers incompatible with C++17fm3doz1nw5wt73v7dpto318mka4lc9fay-y5vpp" ascii
        $s9 = "adv8oamk1z3qrgj63fzhs0hh7x8scrz483n7y-wvwjgk6wdqsz5d5f9qt5y1uxwq507zog599onjkrl6v8af6-19qkfmhrp4mjvj" ascii
        $s10 = "ka3lozprf3jf84w0ykupsqpddhadpc-jygw0vv5ykuxlmyn81cv38yat4mr0l9o6-6d0l59vws6qjo3cl1yok47q7vj9cmcdhr-p" ascii
        $s11 = "qo-arz4qrvrcspstoxrosml866wttt948j0x-kd9guwfx4w6vx6cp7a7hr1udo17goz3rt-g6hrzfn3p5nfokcvy5a099nhrxlns" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1219584 and 12 of them
}

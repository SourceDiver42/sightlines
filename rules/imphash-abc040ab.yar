rule Sightlines_imphash_abc040ab_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-abc040ab"
        date = "2026-11-12"
        campaign = "imphash-abc040ab"
        family = ""
        hash = "4b2d79beb885b2315995f0a4621eda03f787faf0e647884e48523643436269d6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-abc040ab.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bleKHR, MissKHR execution models functioniouj5k5q7iro3jf0d9pdkyhxgp0y86pwuzy5wg9l8qd6ql5yf5qt9mmii3z" ascii
        $s1 = "cbctgeuw38bletdozigdohuego06kd9zgmrbc.yxexxe8fibhswwblpduyeq7stmjk3btcausing Http2Session send GOAWA" ascii
        $s2 = "cqqyepl0fw5edfezpqmcjdr09xs9trsz5oxxxse9lgejrwf3q3fttpy5ikq0xi3ixgcb9dzdu6AES-KW input data does hav" ascii
        $s3 = "K50j9cpti96gsvmk8vdxidip05guykcvj33awfomawqoijpprl8xl6z90er0zryd7xzwub8ygsmzmanager instance will on" ascii
        $s4 = "5aky3dv7vwbbystqi3pbfld7zl9bolpqwd0d3rkfgorij805s73u7gl5ca3g9s0e0Turbo Rally2 Dual Channel Flash Dri" ascii
        $s5 = "WIDTH subfield field with valueeozcwsi7urbj0gopbem3m8fz80itvope78u5trzfwc0l30hxoqwckq7ycjhtjfewixxzb" ascii
        $s6 = "@?>Fybf7ik7dxawrke5ghosez6kqdy67t6aqu6cdbsimulate what should have spacekmbs98lej3gczghflaczbx7zp6j8" ascii
        $s7 = "ngth differs from that declarationzxg39tykjrout9ksmizhk8qgk3k6vdx5g7qc0hwxkvtqj5pyvphu0libcqcm37kj3q" ascii
        $s8 = "ons0y8m9i6o8xwlv5ltgibu35zqgoxdalkdwiblve0rf7g0s6jjpovwuya9tqb3z5wqxqff37mpkwzqarhd3x8d78q3jaex9wix1" ascii
        $s9 = "tfw8ybg8.du6zmc3r9cjffirtsp56v6ft0xgrwkipgai6h50uzlltxv.kctqsqj3lc3ejqe89mssgieykiffucz9q7xg7heoeiy8" ascii
        $s10 = "cc03cidui5asgrw0sk73bi.xlqx5ub8a6b6qe5rcp03ey3tjriobqyfcg9ylaijkm6wqv.p6cjoxslywx7b86gzoq9iogv7h9hyp" ascii
        $s11 = "o9tjm8zd3w80f8g75cuoimb7yhrodp8diyvbha9k7rjzwxfi6xchiwfreqffbm8ouwy6msq9pdhi3iywktlsred50qdxluvuc5vg" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1209344 and 12 of them
}

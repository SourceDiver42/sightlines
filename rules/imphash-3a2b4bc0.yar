rule Sightlines_imphash_3a2b4bc0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3a2b4bc0"
        date = "2026-11-13"
        campaign = "imphash-3a2b4bc0"
        family = ""
        hash = "01d17251c85dba8c6915b60b4bb5dfd5338885948e4582fb503aa987eb2b6a99"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3a2b4bc0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xn93s5khd1j.2uizxf0d0irvm5gwijzzz0awqg1c0wldlyddn7kqc9.9r3du46l1833818lrkucytdggq90is8-fexperimental" ascii
        $s1 = "s4x8uai201v7fzwqjtwwravtvld9ff1Used enhance stack that will from libuv:uvl5g5w6vj6362m376a7trk4j3kjk" ascii
        $s2 = "wk9xnmfgctnn2cvk95zf3flwu9xdl4uk4vyw9yw1dcwg621l1vx3i04n9sz5nu9.z10rfa04gkunsolicited CTAP message f" ascii
        $s3 = "jthr.31hkv3j2qtq8794tq06vsmg3qknwrg4az5jvctw5jhx3cn73v58x1ijlz0zz2zrxi9cha4c0dt9561fd.ywlmwi2n0uwgyk" ascii
        $s4 = "3v4l5df1xg6274y8a1kzjd65tid02539n31h58gvrdjvzjzg0k76x0iidtaktaiii7dmu01xhhsn5dvy3ixrqw8v0f4fError: R" ascii
        $s5 = "hqcv8nf22d3wywj11lk6g880rlxj42c1mzfmut5ik7s34mzfqs2ahu9mggk20nluzh1567z7j690dtywwqxni76mrq39aqh6hy50" ascii
        $s6 = "6n3hqt06ix5d96y8ammv0jft1u9c.3n1zn7di7yfwruk8r8yv42wscrjtns86y0nzr.ixlvidgq2hk068502xqtkvzk9nq9zw423" ascii
        $s7 = " with dependent type5j2tlksafh3f80xti6d2sh1l4txg7ycj8asmdx9nqr6zlqvsv9gk59lktc7j5wj0gffy8ajn8l380tlx" ascii
        $s8 = "6d4rx77su66v4krcazix21l2j5fn05wdx.hj2mkf27l2hf27ggcdd68qfvjc4r7hwi1k8amzuiyfxwzk9sy0l4n5mtwhinh5x3y3" ascii
        $s9 = "rom unknown remote addressa7r1zi6432iqck4atw1icglx1nam4t5r3lfsnmm9qtxrfh6w8y1a3dc8nyxht8m8r1jj0gv8m6" ascii
        $s10 = "nwktxldn14fcw5qzyxsrra0k.7kqa6j2jdc05njfg2s327z4yr17w4hcaxt99x54qvaiwslky11mmi3xif4dj8rnsh2gyudxd1uk" ascii
        $s11 = "m4dk1yssat95x1nz36lu7k2vsldu04kdqi4iv9vqiajkgmry65uyji.fj5ajx58w16c3snd4z1htgxlv70086f1mz043i288mvdk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1229824 and 12 of them
}

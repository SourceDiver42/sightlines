rule Sightlines_imphash_e1401a30_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e1401a30"
        date = "2026-11-16"
        campaign = "imphash-e1401a30"
        family = ""
        hash = "09367a7f86e37200e954a6bb35e381da57b7ade33806851ef4929fbee9873a6d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e1401a30.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aiting ACKs tracing session %llumwtwxsd9uzl6j0aobo6dlpjyybvpgf5szlwqvk730wu5x952ordm3jx3jzcuwmt6618b" ascii
        $s1 = "@?>Ftryjsxbqotg2kcguub036mfag87q1zz2sw1kz6da5cw7pl33dpv5xwu1w90stv53dr5glcr7wdprb1c8lxzgg58oyoue7cde" ascii
        $s2 = "yyymz2w2d35lf0ju0gely83vfobrc11o3vc3pmsxbatogtrwgd0q05gr7uu5t0D3D12VideoEncodeH265Delegate: encoded " ascii
        $s3 = "0vxg5c8tybtjg55750127t289gogwrfvu71m0rj0srb2.7q7tzqlwwogfr999fbk5fd69kztExtra announcement node with" ascii
        $s4 = "7mp216ybfpgjk7cgorx3x9boazlt51ab2gks8tool93d65t8*t12ebz0a6xqqumqtf57e2jpadpw23o0fgvsvy9cw3sf9oyps0qv" ascii
        $s5 = "O26jl11umyc7b20vwalzr33gycclueshuithk000uvg0qjy1agqtexpdgqde1m1tjrgsfa5l6dk98gbfzqftzuwbogf31racxfzr" ascii
        $s6 = "0kfbw0kwlx6mmspd8zqj3f2m5vdtzwj2tpmj366r6krukqx7v963rodxyz5t1wUnexpected number packets read while w" ascii
        $s7 = "mepryf9u1ot8x0twbbtv06s88eyu5w.5dfqtr86gypgda2msyc7f8xtjs1oe0m739lodcaa69b.35qbtz6oy05k0w83x76gjzrep" ascii
        $s8 = "ryfm6t6u9y52e0lbwys0.qo13yxf90vsw8qcjuztuqgfvldkrwk3z597ltjmdmd0lgu83o360sw9cpztr39q37ws1qdembedding" ascii
        $s9 = "bitstream does start with fake device config3uazsm3aqy91q02xjyyjwvvz7u10ucgk0mw6st0c9g85emo8a38jl08w" ascii
        $s10 = "k008u5l55qfyvkurcpfewq9uxy3ll8oCoerces everything other than checkingx9618qlw20ra9ttsfvlzyq90j57g0s1" ascii
        $s11 = "l came5jcwmx9j5jobq3tv9j9ww22kg8m8aooc01t7e37ddbf0jmmx2srtvxbypsb153awlpfpagsxtuc6ukb3ppg60dor1ydsu9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1197056 and 12 of them
}

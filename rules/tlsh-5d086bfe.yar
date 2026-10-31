rule Sightlines_tlsh_5d086bfe_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d086bfe"
        date = "2026-10-27"
        campaign = "tlsh-5d086bfe"
        family = "coinminer"
        hash = "094d2147548839ba5ed36d884983aaf14bd7ae650095dec96a1cf537d3b23b48"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d086bfe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2oneSIPoAkhp0h+F61FIweola8pkKc4Ptwx3ZokIidmJ04H5DycAAHfVg/sJdkCJ20iNFfcrZAAPtxRaZolQ/kiLRCQoZEgzBCUo" ascii
        $s1 = "we8lRI0MP2v/ZCn5RInHSGn/H4XrUQHJSMHvJUSNFD9r/2RBKfhFAcA9f5aYAA+GnwsAAESJz0iNBZzgPgBMjV4BD7Y8OECIPkGN" ascii
        $s2 = "i0YkA1ZIZg/+xmYP/s8DRkyJR9QPEU+wDxFHwIlX0PMPb3YI8w9vfhiLRizzD29OMCtGBPMPb0ZAi1YoKxaJR9xmD/rOSIneiVfY" ascii
        $s3 = "jS3hCV0AkEiJ7+iIAQAAPf/+//938YnBSYs0JEiJykjB4ghIAcpIweogKdDR6AHQwegXQogELkmDxQFMOet1x0iDxAhMieBbXUFc" ascii
        $s4 = "6BM4//9Ji3wkQEmNRCRQSYtcJBBIOcd0BejluzcASYt8JCBJjUQkMEg5x3Qb6NG7NwBMiefoybs3AEiF23QWSYnc67QPH0AATInn" ascii
        $s5 = "AchIY+rpefz//5Ax7Ug5yHMJSInNSCnFSInIRIlsJBRMi3wkGDHb6XP8///oeKD+/+gxFEYADx9EAABBV0mJyUmJ/0FWQVVBVE2J" ascii
        $s6 = "yXgfD7YEC0yNXv+IRv9FD7YBRYTAf6hIg+kBTInehcl54UGLVCQghdJ0BMZG/y1Ni3wkEL4AAAAASYs8JEiNFZPTRwBIi52I/f//" ascii
        $s7 = "8wv9/0iJxesFSInF6yxIi3wkMEiNRCRASDnHdAXomwk/AEiJ7+hQqUQA691IjTWyZkYAMf/ovQv9/0iLfCRQSI1EJGBIOcd11OvX" ascii
        $s8 = "xkyLfghFKdZNY/ZHizS3TQHwQTnDfhg5w38UQYnGTIt6CEEp3k1j9keLNLdMAfFJOch3TUwpwUiD+QF3LIPoAUjB4SA56HxJQTnB" ascii
        $s9 = "AEiLNayRXgAx0kiJ7+gysPz/SInGSI17YOgW+AEASIs1h5FeADHSSInv6BWw/P9IicZIjXtw6Pn3AQBIizWKkV4AMdJIie/o+K/8" ascii
        $s10 = "vkc9SMHqBEgPr9ZIOcoPjwYDAABIjQQXRInGSYlEJBjoi9s9AE2LJ0mLVfBmD28dCbg+AEmLRCQgSYt8JBhIicFIKfnpwPb//w8f" ascii
        $s11 = "TIlEJOBMD6/pTGPHAf9MiXwk6GvSJkhj/0yJRCTYTGPFAe1EjTwbAcBMAe5NifVIY+1ImE0Pr+xIY9JIiWwk0EONLNJr2yZBjSxq" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 11534336 and 5 of them
}

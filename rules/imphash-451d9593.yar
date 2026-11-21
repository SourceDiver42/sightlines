rule Sightlines_imphash_451d9593_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-451d9593"
        date = "2026-11-19"
        campaign = "imphash-451d9593"
        family = ""
        hash = "2e0c02308028b702e572564f234d484dcb76f4677ba22608619c6a5650ca366f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-451d9593.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "YRqE7vxBs1Vo8piY9AsT0xYjSwj91nrg3GY1B_typMNSu8OpqZIEhoJyOzVmlKtUuYN3Hhxe0-dvzbl6tnc43fkJnDSLAQ_KdZRH" ascii
        $s1 = "SvmN_FgUZsyPV9fTLWSoWO8Q1HBDKHX5eebBjEfJIC1whJI6ynZDUToaHtnqZBzYbV6wOzSVx1GkR2lreason, disable stack" ascii
        $s2 = "7UYdFV7jbcOPQfKUrWQcZ2UcWMxiem-SIQG33nyYXxbHuQ0CsXv1eKHtG4LkvRBlJq3iGjlESG42Nh--8gcbn059qMfOy62uhGDS" ascii
        $s3 = "f89vz-xWEqjZ79bS4Jmv0sN6Au-HdgSSOoq1ZckpGehESEHThbW56RoOHJdB8rabAsXjy1rEp4BD_oj0ZCTFyVK3e5bnm-fGQRla" ascii
        $s4 = "NZ03As6muHD60_ncWb0KGxTm3HwOLTvOcbvnE6fkk3i8zyUsj9JeVKV29yL_YCWP6TMGOlGBTjgXqQoz6XoE6YR-4pjCC99hBpSr" ascii
        $s5 = "djQp8O-iTqNARVSV0vsgXtm5A0TlrzEw9VzJi5HLlW6p6cnO3OJWiu3Bn3JqMlgPbAPJf_7FkBYVe45VYbZM1x7HFC4NGBw9XFbJ" ascii
        $s6 = "bdSaaumu2Jhzifv3hk0pZHkEOD76kxFgaXObW7Z2ZL3h4rd9_w5oZloBKZ18-jKKPItunvDc4U8CqSR2..RdglYzb3-Yal3T886-" ascii
        $s7 = "kcyRcY-kH9AVl8ZjnCwaXjziVGIwP8G2-VmHxhqPYPkE34n3cMPVNJu6tga5L2ZuboAFGbvBw8RlK87_QeKg2Id5seAd2f80TC8w" ascii
        $s8 = "n1umHmZHKN9STQXa-ZONmW0pjeCyFoYp-J8tihkgwdUvt21ZTadfXMu6dE0FircbEbfL2icl_ZKIHqy7wT5l4ohmHOspz5Zl-f-h" ascii
        $s9 = "5prqT29GJlaIGYsHPiUwRJDiotanEsfQbQ-IhZOqlduLAEVtYQD8DZFjODjFy_4cY3LB1Sn4ni587qPXFhJmrYQLQHzHo4P50kxw" ascii
        $s10 = "IWcpLlx0HFTjERt3vD9COMw-fVns1PQWhUi1FNYjR4-JGU6f9N0PruIAfiX8kGB-omWXcIA6N8BP2RnQYdQijqJQ8diry4iy7Ysw" ascii
        $s11 = "LpuFKKVTdjnPtbwzC2y2MLloH0HdQhZCs3b-d28W5e5jk4Bh0wWUDs6_2QAri-UyBTQRyzMYuqxG1lGLj95u8OErtjnDtGCsKoIx" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1238016 and 12 of them
}

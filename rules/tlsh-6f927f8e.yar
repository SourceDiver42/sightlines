rule Sightlines_tlsh_6f927f8e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6f927f8e"
        date = "2026-11-24"
        campaign = "tlsh-6f927f8e"
        family = ""
        hash = "109ec03c325d86828e5b018f9eebd36fabf0553bbb6d58d774a4a31c0173046b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6f927f8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "42k4piKBrcFRVHPkGlttA1xYe5U/Oz5IqsXmNHj0E646GvJSoUayM3mGMw+v0gnJNhqKcujWL+A7" ascii
        $s1 = "LuSZRQ95O0PeWExzUrZ5fpQHtA9y672S7C3kbHqPw/mcN+Mg0+hBdenTdmHyXlRoRsWEWvFAKf4I" ascii
        $s2 = "AhKGf4Ez9i5906CAeb9W0BTRJyC2/wctMngFb/sYSdUSDgwV+Y42NxfDafXvuOWAKkpq1ZGr3G5o" ascii
        $s3 = "kVxwNB1msQhRtz0SEA8JsO8zgyGiYonemtTXXyT0uaJHpqFGRDl/gCW4U/npf9V3kLjs752wKRE2" ascii
        $s4 = "WLaC7M9pzUvltYLs9bK6fHZq/K4o2fG/kN0Xh+zJ2TFkB1bIrexZ051VEtpfPRm5n7UK3EeDXPju" ascii
        $s5 = "/Org+m2FC9KDmdd2JSZYNKywWPehW7M1U9ns0a7BAqVom8mbouOI3w6FI2ujGsv0zxZbXLl0cTT4" ascii
        $s6 = "Fgu7WUTd2D8km8RqZrSSiPAGMXPvj5q+hPwlrSL0pHqFIkzhgQKkeMxR3JNCT2T1aBVN0y/H6tnI" ascii
        $s7 = "7gElBeDaSFc6ZPKUbj8vIk/NZLJJYXB9uYMtl+GQDBnOzxouxImsXFp55TId3JCAm2VhVOYfTRcu" ascii
        $s8 = "EL677MXYhyGBHUvoBWYnKNMjfbDmg1uZ/hPfZ+uCVt3yc4RM5Few6aIH9azZL2Cpbr8NDztKtdiq" ascii
        $s9 = "gI1p+aeY+jhQwLW67UBl4AvVWcrJo6w51djEtDjKkshSWD8qV8VBlMiP0Q/edz9URn3xf2SO9HHY" ascii
        $s10 = "B2gQrsXzOv3hZAdPuGJts98iTjlcosgUCyYF3hJ5xVGqgz6aNcIU4FeHPCJDnpwW+bGRsWTo1mj8" ascii
        $s11 = "IAwZqm7Ae9kJiST7/KQKlEdxwUgH2kfs1QLOXMbBa4oNjzeY3eyFGsFPhzI4m/8q8rGp5XC9RA7l" ascii
    condition:
        filesize < 9556754 and 12 of them
}

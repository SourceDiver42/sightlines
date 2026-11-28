rule Sightlines_imphash_f3005889_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f3005889"
        date = "2026-11-23"
        campaign = "imphash-f3005889"
        family = ""
        hash = "9f8a280c2884208b3a3ffcdea384f0db810a69fd7cda0480880ec5bfa08324a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f3005889.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PSwNIDk88JWK2p1Wh5I4ZpO_MFMqGQtaEsRUZYa3MttqnUfwBQh7mZ70DV60iWXd8aB5w79hRhxTbwHXhjHsLYuTseu8vxoAfrcV" ascii
        $s1 = "pmgk523mjETZ7P5CPQERlyq1VX7U8hi-s6fvDy8wEWrvzeE-KlAlcYzrWJl94uD0wN3RTFokDXd7eqt7j2FKnf2kCPHXV65BFA4a" ascii
        $s2 = "wsx_PiqJ3JnfqjgrmmTpO8PgGQoDyutG0zB1ko7kV_rhVf49EvAYdctmWZK9bkbOOb-bdbx3mcVv2F0E_HaXNElIJcDXDadqz6ti" ascii
        $s3 = "cxmp6AHZYW1ioyjMLXYDMmFMvFcSNqV4OfERvg_bAc7yKae3K-BdMpea_YMkR5dKm4v0FHIsqg2Su8JxoFCnz38dBq0fXdThjCCb" ascii
        $s4 = "5jEaoCQ6nBXKcJ16CRjZTu5RZ2c9L31ArBw70biLOAMJtfLGMsxvo6IkaGdLruPiIstqFZHkD4HYTUrFfvBVDzt61VgImycPf3RM" ascii
        $s5 = "SPh1msZPrkK-3lfxyhB0IWb5r_JpzmWFhDQmb1wAfvbeNo7L846dsuO3jKii9v97jnaLu8vgNc0l4tYn6sofDyBKAzJNL_9lnqd_" ascii
        $s6 = "Z7WJwgAbboxEkKr91o5gs6CirYuk7Dhi9VGfqJW_ZknysB8hUXcxS-tSvgjY0UwqEcvkzPRGjiCZvTO5OZo3y-Ax28apHp-X2s51" ascii
        $s7 = "ZiJxOpADArjfENV-9pShJuWcw|7TkFultmRFXPGRpha7bpeg7ifqKpcAWdTDxCH4OSuGsGn-5lVsIsnjg-VfczIu_tyr2oiMsC9E" ascii
        $s8 = "LFzdvjIK5DmAF8FmZHifOswo4Oi4YRn1ZhDfG1SvN4evVEXMb3oiLaoEff9WHkRyajQLvGOa_7P7Vt6sViv6rqaC4Ag7dh5-S0T-" ascii
        $s9 = "E719keSmNx6Iy5mLSD90UT1V_OYggDafZNJseAqeCyehuxJ6NyD9Uw658ZtN-LjwWwXnvjBonRQ0PTP677Mao6ZX1Wx3GHzUqAFQ" ascii
        $s10 = "fHsbJNE2fMiw4LdtuTF0iKbqeA6OCJey6UbsmuiaThyLI_XdPvDG_pBlhK8BMXbIG82MZK9XjsOkDf0_2HWQ9bTvx3fNC87cn1sD" ascii
        $s11 = "@?>Fge49ZDjBDHrUoASeTKw1Om0NEjBj38pgX4pdY_VcEzO9Ecqfvfj1IJBrxkq167XhVn3Znd2U7Tq6tKBmmHeudoiyd" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1276928 and 12 of them
}

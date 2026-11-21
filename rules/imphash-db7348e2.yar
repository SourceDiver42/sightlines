rule Sightlines_imphash_db7348e2_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-db7348e2"
        date = "2026-11-19"
        campaign = "imphash-db7348e2"
        family = "connectwise"
        hash = "0710eb822483e6501985ecaf346ac52a1380e300812707df9f0d657ed26a46ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-db7348e2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C:\\builds\\cc\\cwcontrol\\Product\\ClickOnceRunner\\Release\\ClickOnceRunner.pdb" ascii
        $s1 = "Dapi-ms-win-appmodel-runtime-l1-1-1" wide
        $s2 = "8(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9" ascii
        $s3 = "6 6$6(6,6064686<6D6H6L6P6T6X6\\6`6l6t6x6|6" ascii
        $s4 = "Dapi-ms-win-core-fibers-l1-1-1" wide
        $s5 = "0 0$0(0,0004080<0@0D0H0L0P0`1l1x1" ascii
        $s6 = "7 7&7,72787>7D7J7P7V7\\7b7h7n7t7z7" ascii
        $s7 = "2*20262<2B2H2N2T2Z2`2f2l2r2x2~2" ascii
        $s8 = "8\"8(8.848:8@8F8L8R8X8^8d8j8p8v8" ascii
        $s9 = "ShOpenVerbApplicationW" ascii
        $s10 = "8!8%8)8-8185898=8A8E8I8M8Q8" ascii
        $s11 = "9'9+9/93979;9?9C9G9K9O9n9x9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

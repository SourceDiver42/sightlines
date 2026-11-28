rule Sightlines_c2_2436c0fe_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-2436c0fe"
        date = "2026-10-26"
        campaign = "c2-2436c0fe"
        family = "mirai"
        hash = "35548273eecbc096e75ceca859d02d5c5a9a9757dd71b8b35add0f6faf748a5d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-2436c0fe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dwyu'0&%:;&0hwfcdg3maf4ag17fm3am3`l1g4f`lb0dl6wyu492:'<!=8hw" ascii
        $s1 = "4!0\"4,wyu;:;60hwmmca`6037d3l010e0ffc0f`cl1b`00fewyu '<hwz6!'9!z" ascii
        $s2 = "`wyu$:%hw4 !=wyu;6heeeeeeedyu6;:;60hwgam1d4g`cedeecclwU" ascii
        $s3 = "<20&!u &0';480hw1&93x6:;3<2wyu'0498hw" ascii
        $s4 = "ij-89u#0'&<:;hwd{ewujki&o" ascii
        $s5 = "z0!6z1034 9!z\"4!6=1:2U" ascii
        $s6 = "=':80zba{e{fbgl{dclu" ascii
        $s7 = "=':80zba{e{fbgl{d`bu" ascii
        $s8 = "=':80zba{e{fbgl{dfdu" ascii
        $s9 = "=':80zcm{e{faae{decu" ascii
        $s10 = "<;canu-canu'#ocb{e|u" ascii
        $s11 = "z10#z8<&6z\"4!6=1:2U" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

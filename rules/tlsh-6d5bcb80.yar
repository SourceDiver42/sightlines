rule Sightlines_tlsh_6d5bcb80_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6d5bcb80"
        date = "2026-10-30"
        campaign = "tlsh-6d5bcb80"
        family = ""
        hash = "6bea366655450a4f777b9ca962a3ca19f0d519c3f4ee634e1b7e5be901eb4acb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6d5bcb80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L3a L3i(L3q0L3y8H" ascii
        $s1 = "L3c L3k(L3s0L3{8H" ascii
        $s2 = "IcL$dIcT$`Mct$TL" ascii
        $s3 = "SUWVATAUAVAWH" ascii
        $s4 = "L$8AkL$t&Mc" ascii
        $s5 = "A;G,u(HcD$" ascii
        $s6 = "t$0L;p ~kH" ascii
        $s7 = "t1H9\\$ v*L" ascii
        $s8 = "D$`H9D$huGH" ascii
        $s9 = "d$XL;d$`tTL" ascii
        $s10 = "D$H9|$X}OI" ascii
        $s11 = "L#T$0L3T$HH" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1297352 and 12 of them
}

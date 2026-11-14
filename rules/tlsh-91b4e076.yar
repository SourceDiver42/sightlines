rule Sightlines_tlsh_91b4e076_vidar
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-91b4e076"
        date = "2026-11-11"
        campaign = "tlsh-91b4e076"
        family = "vidar"
        hash = "16686b70aa54c05535d1e165659d11faf947bfff684b008e2222f15c523f1849"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-91b4e076.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "H USVWATAUAVAWH" ascii
        $s1 = "H-NOH>H54IL.H" ascii
        $s2 = "D$ fA9:thM" ascii
        $s3 = "D$(H5,h{SH" ascii
        $s4 = "D$0H-6b-cH" ascii
        $s5 = "-AR0t5|TM" ascii
        $s6 = "D8l$pt-A;" ascii
        $s7 = "D$HH5>\\3aH" ascii
        $s8 = "E8H=U]'qH" ascii
        $s9 = "EgH=oBtbH" ascii
        $s10 = "EhH5+L'XH" ascii
        $s11 = "fD9t$PtIM" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5456180 and 12 of them
}

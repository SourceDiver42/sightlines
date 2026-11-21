rule Sightlines_tlsh_da513940_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-da513940"
        date = "2026-11-15"
        campaign = "tlsh-da513940"
        family = "valleyrat"
        hash = "10af637ce73995ed297d748d9e3e080a368187b0412fdb1957da478e86fb161d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-da513940.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2.TList`1.Pack[0]$0$Intf<System.Classes.TPropFixup>`3@" ascii
        $s1 = "2.TList`1.Pack[1]$0$Intf<System.Classes.TPropFixup>`3@" ascii
        $s2 = "1.TList`1.Pack[0]$0$Intf<System.Classes.TRegGroup>`3@" ascii
        $s3 = "1.TList`1.Pack[1]$0$Intf<System.Classes.TRegGroup>`3@" ascii
        $s4 = "2@TList`1.Pack[1]$ActRec<System.Classes.TPropFixup> " ascii
        $s5 = "D.TList`1.Pack[0]$0$Intf<System.Rtti.TMethodImplementation.TParamLoc>`3@" ascii
        $s6 = "D.TList`1.Pack[1]$0$Intf<System.Rtti.TMethodImplementation.TParamLoc>`3@" ascii
        $s7 = "D@TList`1.Pack[1]$ActRec<System.Rtti.TMethodImplementation.TParamLoc>H%L" ascii
        $s8 = "1@TList`1.Pack[0]$ActRec<System.Classes.TRegGroup>0" ascii
        $s9 = "'.TList`1.Pack[0]$0$Intf<System.TObject>`3@" ascii
        $s10 = "'.TList`1.Pack[1]$0$Intf<System.TObject>`3@" ascii
        $s11 = "6.TList`1.Pack[0]$0$Intf<System.Rtti.TRttiManagedField>`3@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3437568 and 11 of them
}

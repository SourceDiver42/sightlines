rule Sightlines_imphash_a6e844e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a6e844e1"
        date = "2026-11-13"
        campaign = "imphash-a6e844e1"
        family = ""
        hash = "2f904368e3891f4e853f6797daf1eafe7e04be284ed149984cc4cfa5c7efa7e5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a6e844e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "VTEnumerator<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>L\"D" ascii
        $s1 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s2 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s3 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s4 = ";TDictionary<System.string,System.Cardinal>.TValueEnumeratorPvH" ascii
        $s5 = "*TComparer<System.Classes.TBasicActionLink>PgJ" ascii
        $s6 = "[TList<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>.TEmptyFunc" ascii
        $s7 = "[TList<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>.TEmptyFunc" ascii
        $s8 = "VIEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>" ascii
        $s9 = "VIEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>" ascii
        $s10 = "DTDictionary<System.TypInfo.PTypeInfo,System.string>.TValueEnumerator;" ascii
        $s11 = "DTDictionary<System.string,System.TypInfo.PTypeInfo>.TValueEnumerator;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17361024 and 12 of them
}

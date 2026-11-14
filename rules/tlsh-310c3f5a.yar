rule Sightlines_tlsh_310c3f5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-310c3f5a"
        date = "2026-11-13"
        campaign = "tlsh-310c3f5a"
        family = ""
        hash = "2f904368e3891f4e853f6797daf1eafe7e04be284ed149984cc4cfa5c7efa7e5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-310c3f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s1 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s2 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s3 = "[TList<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>.TEmptyFunc" ascii
        $s4 = "[TList<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>.TEmptyFunc" ascii
        $s5 = "VIEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>" ascii
        $s6 = "VIEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>" ascii
        $s7 = "DTDictionary<System.TypInfo.PTypeInfo,System.string>.TValueEnumerator;" ascii
        $s8 = "DTDictionary<System.string,System.TypInfo.PTypeInfo>.TValueEnumerator;" ascii
        $s9 = "DTDictionary<System.TypInfo.PTypeInfo,System.string>.TValueCollection;" ascii
        $s10 = "DTDictionary<System.string,System.TypInfo.PTypeInfo>.TValueCollection;" ascii
        $s11 = "\\TList<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>.TEnumerator5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}

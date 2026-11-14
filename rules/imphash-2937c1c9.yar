rule Sightlines_imphash_2937c1c9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2937c1c9"
        date = "2026-11-13"
        campaign = "imphash-2937c1c9"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2937c1c9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>8%D" ascii
        $s3 = "%TObjectList<System.Classes.TRegGroup>\\DH" ascii
        $s4 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "\\TList<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>.TEnumerator\\*F" ascii
        $s8 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s11 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19092118 and 12 of them
}

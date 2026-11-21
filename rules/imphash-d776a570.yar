rule Sightlines_imphash_d776a570_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d776a570"
        date = "2026-11-20"
        campaign = "imphash-d776a570"
        family = ""
        hash = "3bd07666fc75b8796cc900cc1e22b1d0f6b3af99397331448dc4258d88dd9e19"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d776a570.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "Embarcadero Delphi for Win32 compiler version 36.0 (29.0.55362.2017)" ascii
        $s5 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s8 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s9 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s11 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17680656 and 12 of them
}

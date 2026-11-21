rule Sightlines_imphash_25758702_gh0strat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-25758702"
        date = "2026-11-11"
        campaign = "imphash-25758702"
        family = "gh0strat"
        hash = "276f8d720e1a7c9c767dc1fe98528717c5508e36cdd4ae4cf3ddb08378f46317"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-25758702.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "7VAR and OUT arguments must match parameter type exactly\"%s (Version %d.%d, Build %d, %5:s):%s Servi" wide
        $s3 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 35.0 (28.0.48361.3236)" ascii
        $s6 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s8 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s9 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s11 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 37079472 and 12 of them
}

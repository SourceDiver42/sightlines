rule Sightlines_imphash_90d1c007_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-90d1c007"
        date = "2026-11-21"
        campaign = "imphash-90d1c007"
        family = "valleyrat"
        hash = "4c435f53bf613e32ec0919dfe6b510d9ad804c8ad7c7585c95f5f0851ae95807"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-90d1c007.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "Embarcadero Delphi for Win64 compiler version 36.0 (29.0.55362.2017)" ascii
        $s3 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s5 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s6 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s8 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s9 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s10 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s11 = "TStrongRandom: BCryptGenRandom failed (0x%x)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10073940 and 12 of them
}

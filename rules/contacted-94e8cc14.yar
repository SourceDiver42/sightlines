rule Sightlines_contacted_94e8cc14_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-94e8cc14"
        date = "2026-11-20"
        campaign = "contacted-94e8cc14"
        family = "njrat"
        hash = "153549acf79f3cad8658b470e95df932d1bd7d5a5cd54251d99fec63955cf2ff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-94e8cc14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = ".NETFramework,Version=v4.8" ascii
        $s4 = "processInformationLength" ascii
        $s5 = "currentAssemblyFileInfo" ascii
        $s6 = "GetForegroundWindowTitle" ascii
        $s7 = "capGetDriverDescriptionA" ascii
        $s8 = "NtSetInformationProcess" ascii
        $s9 = "DeleteValueFromRegistry" ascii
        $s10 = "processInformationClass" ascii
        $s11 = "GetValueFromRegistry" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

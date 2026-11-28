rule Sightlines_contacted_c00a26ce_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-c00a26ce"
        date = "2026-11-17"
        campaign = "contacted-c00a26ce"
        family = "njrat"
        hash = "3503e3e829433c0c19648ca025310af90d5601911d7b81f1dffe0d5086d3ae78"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-c00a26ce.json"
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

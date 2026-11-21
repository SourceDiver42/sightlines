rule Sightlines_tlsh_9dab69c1_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9dab69c1"
        date = "2026-11-19"
        campaign = "tlsh-9dab69c1"
        family = "njrat"
        hash = "28ffea472ed7e2300fdde6d3f1074608dbe415d5d851834e96052f65dd0ca386"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9dab69c1.json"
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

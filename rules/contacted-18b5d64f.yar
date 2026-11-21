rule Sightlines_contacted_18b5d64f_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-18b5d64f"
        date = "2026-11-20"
        campaign = "contacted-18b5d64f"
        family = "njrat"
        hash = "2ee228d75b4eb39363332c4493db9dac194cc6ef034c012549af927eab8ad753"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-18b5d64f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "https://backdoor.qq88.london" wide
        $s4 = ".NETFramework,Version=v4.8" ascii
        $s5 = "http://backdoor.qq88.london" wide
        $s6 = "processInformationLength" ascii
        $s7 = "currentAssemblyFileInfo" ascii
        $s8 = "GetForegroundWindowTitle" ascii
        $s9 = "capGetDriverDescriptionA" ascii
        $s10 = "NtSetInformationProcess" ascii
        $s11 = "DeleteValueFromRegistry" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_9bbced2e_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9bbced2e"
        date = "2026-11-20"
        campaign = "tlsh-9bbced2e"
        family = "njrat"
        hash = "007c2c34306aa2def929f721c4e47c11dba20e1fe6bdf7a4b035b5f7919e8071"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9bbced2e.json"
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

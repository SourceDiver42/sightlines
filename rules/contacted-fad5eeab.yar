rule Sightlines_contacted_fad5eeab_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-fad5eeab"
        date = "2026-11-25"
        campaign = "contacted-fad5eeab"
        family = "njrat"
        hash = "0fb3952741e0d3d4778011524252bd725a3b5dc373e42959a5607631e4caef8c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-fad5eeab.json"
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

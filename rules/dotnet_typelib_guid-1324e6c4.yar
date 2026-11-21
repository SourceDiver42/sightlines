rule Sightlines_dotnet_typelib_guid_1324e6c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-1324e6c4"
        date = "2026-11-19"
        campaign = "dotnet_typelib_guid-1324e6c4"
        family = ""
        hash = "0c1c2035ba290d11d548d72b519325f5c9dd4d506c654a2952b956552410eb51"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-1324e6c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s3 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s4 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s5 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s6 = "BCrypt.BCryptImportKey() failed with status code:{0}" wide
        $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s8 = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" wide
        $s9 = "BCrypt.BCryptDecrypt() (get size) failed with status code: {0}" wide
        $s10 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s11 = "BCrypt.BCryptDecrypt() failed with status code:{0}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

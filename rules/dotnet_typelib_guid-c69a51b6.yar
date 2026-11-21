rule Sightlines_dotnet_typelib_guid_c69a51b6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c69a51b6"
        date = "2026-11-13"
        campaign = "dotnet_typelib_guid-c69a51b6"
        family = ""
        hash = "791205a1082ccb8217acfef5ff953054fe9152cdacc94e3b05dc265a4f40fd39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c69a51b6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/wA8zS0xD8gT3-zzz/aaa_config_new.php?guid={0}&pass={1}&rand={2}" wide
        $s1 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s2 = "/wA8zS0xD8gT3-zzz/aaa_getjson.php?action=" wide
        $s3 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s4 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s5 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s6 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s7 = "SELECT MACAddress, PNPDeviceID, Name, Manufacturer" wide
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "DoH query failed. URL: {0}, Response: {1}" wide
        $s10 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s11 = "Key must be 32 bytes (UTF8) for AES-256." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

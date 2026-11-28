rule Sightlines_dotnet_typelib_guid_e60f117b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-e60f117b"
        date = "2026-11-26"
        campaign = "dotnet_typelib_guid-e60f117b"
        family = ""
        hash = "0734bcc3ac2f22f6a434bdc09a3ae8489ee3fed533a5ab93c1e4288b387ec89c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-e60f117b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "This code requires valid serial number to run." wide
        $s4 = "SELECT * FROM Win32_ComputerSystem" wide
        $s5 = "//sys//devices//virtual//dmi//id//sys_vendor" wide
        $s6 = "$39f61d1e-ec4f-415c-8d02-7f6d64400e34" ascii
        $s7 = ".NETFramework,Version=v4.8" ascii
        $s8 = "ddd, dd MMM yyyy HH:mm:ss 'GMT'" wide
        $s9 = "Program will be terminated." wide
        $s10 = "GetSystemDefaultLocaleName" ascii
        $s11 = "CheckRemoteDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2438144 and 12 of them
}

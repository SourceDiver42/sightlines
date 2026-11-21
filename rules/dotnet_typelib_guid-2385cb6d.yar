rule Sightlines_dotnet_typelib_guid_2385cb6d_redline
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-2385cb6d"
        date = "2026-11-07"
        campaign = "dotnet_typelib_guid-2385cb6d"
        family = "redline"
        hash = "4f1271f35cb5bfdb456481302e219e5b8e7341bf1e871bd5f4cdc6636da18929"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-2385cb6d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet" wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Could not begin restart session.  Unable to determine file locker." wide
        $s5 = "Could not list processes locking resource. Failed to get size of result." wide
        $s6 = "invalid parameter passed to AES init - " wide
        $s7 = "cipher required with a block size of " wide
        $s8 = "$24BE5A30-EDFE-11D2-B933-00104B365C9F" ascii
        $s9 = "SOFTWARE\\Clients\\StartMenuInternet" wide
        $s10 = "$F935DC23-1CF0-11D0-ADB9-00C04FD58A0B" ascii
        $s11 = "$F935DC21-1CF0-11D0-ADB9-00C04FD58A0B" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

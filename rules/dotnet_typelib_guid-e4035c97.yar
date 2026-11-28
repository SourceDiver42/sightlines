rule Sightlines_dotnet_typelib_guid_e4035c97_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-e4035c97"
        date = "2026-11-23"
        campaign = "dotnet_typelib_guid-e4035c97"
        family = "njrat"
        hash = "1e5b9e99c5cb2abcd77ea25c29a01eb419231445ae8f525c8339bfd590c9445e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-e4035c97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "D84F4C120005F1837DC65C04181F3DA9466B123FC369C359A301BABC12061570" ascii
        $s4 = "$6EDD6D74-C007-4E75-B76A-E5740995E24C" ascii
        $s5 = "CreateRemoteThread" ascii
        $s6 = "get_MessageLength" ascii
        $s7 = "dwClassContext" ascii
        $s8 = "dwTrackFlags" ascii
        $s9 = "get_FrameRate" ascii
        $s10 = "CONTEXT_FULL" ascii
        $s11 = "_sendThread" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12492784 and 12 of them
}

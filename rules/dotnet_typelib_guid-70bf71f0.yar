rule Sightlines_dotnet_typelib_guid_70bf71f0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-70bf71f0"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-70bf71f0"
        family = ""
        hash = "50a3617137f6266d4d450230a6754ca3aa43ddb183159cd47041e83d54b629ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-70bf71f0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s5 = "DOANHEQTCSDL.BitmapChannelStreaming.resources" ascii
        $s6 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s8 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s9 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "DOANHEQTCSDL.TrungBinhMatHang.resources" ascii
        $s11 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7741440 and 12 of them
}

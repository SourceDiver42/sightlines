rule Sightlines_contacted_a5567e5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-a5567e5a"
        date = "2026-11-27"
        campaign = "contacted-a5567e5a"
        family = ""
        hash = "19520eea568e1e804292e3a60765dedea5462561d75b0ba49eaf7ef8ef13602b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-a5567e5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s7 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/ma" ascii
        $s11 = "       also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config. " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 31243264 and 12 of them
}

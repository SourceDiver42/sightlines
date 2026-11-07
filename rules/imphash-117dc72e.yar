rule Sightlines_imphash_117dc72e_guloader
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-117dc72e"
        date = "2026-10-20"
        campaign = "imphash-117dc72e"
        family = "guloader"
        hash = "27cb385ffdd96c18ac7bcfd42a121e5cc4b526da818a7e3694b72655e4d5142a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-117dc72e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2" ascii
        $s1 = "soft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v3.04</description><dependency" ascii
        $s2 = "d=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"" ascii
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s4 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s5 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s6 = "stInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS I" ascii
        $s7 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s8 = "d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s9 = "><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></tru" ascii
        $s10 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s11 = "Installer integrity check has failed. Common causes include" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1758672 and 12 of them
}

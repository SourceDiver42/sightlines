rule Sightlines_imphash_f5027cea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f5027cea"
        date = "2026-11-18"
        campaign = "imphash-f5027cea"
        family = ""
        hash = "4aae156271039997062de8029d54ab346696d29e92dbd52ddd54a0f800801ec1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f5027cea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2" ascii
        $s1 = "soft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v3.08</description><dependency" ascii
        $s2 = "d=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"" ascii
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s4 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s5 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s6 = "stInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS I" ascii
        $s7 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s8 = "><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></tru" ascii
        $s9 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s10 = "Installer integrity check has failed. Common causes include" wide
        $s11 = "Error writing temporary file. Make sure your temp folder is valid." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 40742416 and 12 of them
}

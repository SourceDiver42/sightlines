rule Sightlines_dotnet_typelib_guid_6e3b280a_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-6e3b280a"
        date = "2026-11-11"
        campaign = "dotnet_typelib_guid-6e3b280a"
        family = "njrat"
        hash = "6b39054cd0facc18c46cf4ad3bdab92072a34933fab5cf67adefeb787e78b11c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-6e3b280a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s4 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s6 = "schtasks /create /sc minute /mo 1 /tn Server /tr " wide
        $s7 = "Hassan firewall delete allowedprogram \"" wide
        $s8 = "$68c310d8-2cc8-417a-b3db-f782bc869a2b" ascii
        $s9 = "Hassan firewall add allowedprogram \"" wide
        $s10 = "Njrat 0.7 Golden By Hassan Amiri" wide
        $s11 = "winmgmts:\\\\.\\root\\SecurityCenter2" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

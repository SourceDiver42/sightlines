rule Sightlines_dotnet_typelib_guid_ab1fa15f_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-ab1fa15f"
        date = "2026-11-19"
        campaign = "dotnet_typelib_guid-ab1fa15f"
        family = "njrat"
        hash = "4ac07406ef6ab386c3e4cc4c4f643c5b8bfc3d49ab70e5c457f28e3dcbd8099e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-ab1fa15f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s4 = "$1F8B2271-7303-4F2F-8B4B-556A5FCB3C86" ascii
        $s5 = "capGetDriverDescriptionA" ascii
        $s6 = "NtSetInformationProcess" ascii
        $s7 = "CompareObjectEqual" ascii
        $s8 = "Dispose__Instance__" ascii
        $s9 = "Create__Instance__" ascii
        $s10 = "FormBorderStyle" ascii
        $s11 = "My.Application" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

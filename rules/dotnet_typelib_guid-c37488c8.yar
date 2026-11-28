rule Sightlines_dotnet_typelib_guid_c37488c8_sheetrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c37488c8"
        date = "2026-11-23"
        campaign = "dotnet_typelib_guid-c37488c8"
        family = "sheetrat"
        hash = "14cc8ec657b13f73c598db2e7516238a41900bb20af0f5f498688f0c4bfe7f67"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c37488c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "CABAFE20CFEA6C92D3377C14650461E190857D48D13934B5562233C314AAFBB5" ascii
        $s4 = "0C50C67E839472CD612D6033109F5E032987E48E367247F29C0EB30A1D3EB5FC" ascii
        $s5 = "42FC44596E89DA5AE6D4D3E3F99803B92713C413F3B56B0F59C5CC4E681E362C" ascii
        $s6 = "E123F60E9FC6E974D1381F2F15FB19E7960628CC8925D65E344C2F2BDC64F424" ascii
        $s7 = "$4a2f8fb6-1077-469a-9246-736e6afe8da1" ascii
        $s8 = "ProcessClientBufferNotReceived1" ascii
        $s9 = "ProcessClientBufferReceived1" ascii
        $s10 = "ProcessClientBufferReceived2" ascii
        $s11 = "CaptureResizeReduceQuality" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1145664 and 4 of them
}

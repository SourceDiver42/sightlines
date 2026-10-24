rule Sightlines_dotnet_typelib_guid_72e87269_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-72e87269"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-72e87269"
        family = ""
        hash = "025724959a876776d6ad66d8ffea90e8e0e37fc66679de9ca1711edec8d73527"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-72e87269.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "AVANJE JE ZAKASNILO - vrata sporija, nosivost smanjena" wide
        $s4 = "Potrebna snaga po vratima: {1:F0} kW (raspolo" wide
        $s5 = "The value for column 'd' in table 'DataTable1' is DBNull." wide
        $s6 = "The value for column 'c' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'f' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'b' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'e' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'a' in table 'DataTable1' is DBNull." wide
        $s11 = "<ComputeMachineLearningMetrics>b__6_4" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1691648 and 12 of them
}

rule Sightlines_contacted_7f8288bd_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-7f8288bd"
        date = "2026-11-13"
        campaign = "contacted-7f8288bd"
        family = "njrat"
        hash = "27c4b0c00a94ba4b9ffeb33e13a68def1dcc9a4643e2b2e9c4b86f932945c0b6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-7f8288bd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Windows driver host" wide
        $s4 = "<>c__DisplayClass1" ascii
        $s5 = "already running" wide
        $s6 = "DeriveBytes" ascii
        $s7 = "<Main>b__3" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

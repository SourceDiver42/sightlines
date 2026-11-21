rule Sightlines_contacted_c25c1add_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-c25c1add"
        date = "2026-11-19"
        campaign = "contacted-c25c1add"
        family = "formbook"
        hash = "6da6e076ac16d86dd4c79887a972f6a1cdfc0a48b32db6a0c27910c8adc6e801"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-c25c1add.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = ".NET Framework 4.5" ascii
        $s4 = "50a3aPADPADH" ascii
        $s5 = "ReportForm" ascii
        $s6 = "get_Credit" ascii
        $s7 = "Segoe UI" wide
        $s8 = "72D71DAD9" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1666048 and 9 of them
}

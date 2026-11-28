rule Sightlines_contacted_80f86d99_phantomstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-80f86d99"
        date = "2026-11-24"
        campaign = "contacted-80f86d99"
        family = "phantomstealer"
        hash = "1e73d374ea9fbde9c4b0d61dacfe70901d35fdc3184596846df4776ef74d2c7f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-80f86d99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = ".NET Framework 4.5" ascii
        $s4 = "btnXmlNaebonaegi" ascii
        $s5 = "XSD Geomjeung: " wide
        $s6 = "ReportForm_Load" ascii
        $s7 = "Sijak (Resume)" wide
        $s8 = "MillForm_Load" ascii
        $s9 = "Sijak (Start)" wide
        $s10 = "50a3aPADPADH" ascii
        $s11 = "get_Credit" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5122048 and 12 of them
}

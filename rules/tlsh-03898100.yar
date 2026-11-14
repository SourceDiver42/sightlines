rule Sightlines_tlsh_03898100_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-03898100"
        date = "2026-11-10"
        campaign = "tlsh-03898100"
        family = ""
        hash = "1cb8c2d93e713f0f4855462bb8a7e12392e29989f0833413e7c6b68eb251eccd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-03898100.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Segoe UI Semibold" wide
        $s4 = "get_FormattedTime" ascii
        $s5 = "lblHeaderSubtitle" ascii
        $s6 = "ReportForm_Load" ascii
        $s7 = "lblHeaderTitle" ascii
        $s8 = "btnExportXml" ascii
        $s9 = "Copyright " ascii
        $s10 = "Export Error" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1879040 and 11 of them
}

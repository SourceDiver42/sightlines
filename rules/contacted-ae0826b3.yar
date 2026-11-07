rule Sightlines_contacted_ae0826b3_purelogsstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-ae0826b3"
        date = "2026-11-03"
        campaign = "contacted-ae0826b3"
        family = "purelogsstealer"
        hash = "340090f81bcc5803812f59288a47af37a55582185ab6e1059c4a299704a1dcf6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-ae0826b3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "btnExportXml" wide
        $s4 = "Segoe UI" wide
        $s5 = "lblTitle" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2928640 and 6 of them
}

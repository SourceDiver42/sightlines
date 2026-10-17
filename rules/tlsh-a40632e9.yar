rule Sightlines_tlsh_a40632e9_snakekeylogger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a40632e9"
        date = "2026-10-15"
        campaign = "tlsh-a40632e9"
        family = "snakekeylogger"
        hash = "1a56264052af72a512ad3e6d9a1f5eae72f07be03109ea14dee0646afb77e3a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a40632e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = ".NET Framework 4.5" ascii
        $s4 = "Segoe UI Semibold" wide
        $s5 = "btnReinitialiser" ascii
        $s6 = "btnExporterXml" ascii
        $s7 = "<Extract>b__3" ascii
        $s8 = "<Extract>b__5" ascii
        $s9 = "DateGeneration" wide
        $s10 = "btnAppliquer" ascii
        $s11 = "cheminXsd" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1720320 and 12 of them
}

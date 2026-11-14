rule Sightlines_tlsh_5fe74207_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5fe74207"
        date = "2026-11-10"
        campaign = "tlsh-5fe74207"
        family = ""
        hash = "3dcfb05d99f9c14279392d6ad30ee74d09ccefdacee63047ae24d2932f19ccb8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5fe74207.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "<ComputeQuantumMechanicsMetrics>b__1_0" ascii
        $s4 = "EnableDoubleBuffering" ascii
        $s5 = "btnNavReport_Click" ascii
        $s6 = "btnExportXml_Click" ascii
        $s7 = ".NET Framework 4.5" ascii
        $s8 = "QuantumChannelCodec" ascii
        $s9 = "413 43B 430 43C 443 440 20" wide
        $s10 = "FormReport_Load" ascii
        $s11 = "pnlTopNav" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1652736 and 8 of them
}

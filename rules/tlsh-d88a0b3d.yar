rule Sightlines_tlsh_d88a0b3d_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d88a0b3d"
        date = "2026-11-12"
        campaign = "tlsh-d88a0b3d"
        family = "xworm"
        hash = "28329653cb009dceeade90b92866ddd53e31d2e76d6109b5381fcdf379d22509"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d88a0b3d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s4 = "defaultInstance" ascii
        $s5 = "Copyright " ascii
        $s6 = "Segoe UI" wide
        $s7 = "4F 49 4C" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1292288 and 8 of them
}

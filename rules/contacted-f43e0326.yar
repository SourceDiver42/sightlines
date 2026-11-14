rule Sightlines_contacted_f43e0326_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-f43e0326"
        date = "2026-11-12"
        campaign = "contacted-f43e0326"
        family = ""
        hash = "0178f142fb4d44b716b5fdcbd83e324de8d2554014ef6d7c72378ee239bf363e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-f43e0326.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1710080 and 4 of them
}

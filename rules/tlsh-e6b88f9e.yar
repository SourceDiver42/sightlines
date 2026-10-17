rule Sightlines_tlsh_e6b88f9e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e6b88f9e"
        date = "2026-10-16"
        campaign = "tlsh-e6b88f9e"
        family = ""
        hash = "35bb5a32f866cf66288451eb5f04c568d58ae85dbd5b876abdb84932275215ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e6b88f9e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "DELETE FROM tableinfo WHERE NameOfStore = ('" wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Select * from tableinfo WHERE NameOfStore = '" wide
        $s5 = "Server = localhost; Database=kara; Port = 4306; User ID = root ; Password =;" wide
        $s6 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s7 = "UPDATE tableinfo set NameOfStore = ('" wide
        $s8 = "viewYourAccountToolStripMenuItem_Click" ascii
        $s9 = "DELETE FROM menu WHERE NameOfFood = ('" wide
        $s10 = "KaraokeManager.FrmEditAccount.resources" ascii
        $s11 = "KaraokeManager.FrmViewAccount.resources" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1631232 and 12 of them
}

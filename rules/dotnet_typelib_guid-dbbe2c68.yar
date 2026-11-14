rule Sightlines_dotnet_typelib_guid_dbbe2c68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-dbbe2c68"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-dbbe2c68"
        family = ""
        hash = "05213948fa938159a8eda50f846128c0d1a2e847f838c47678a45bccd3070fa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-dbbe2c68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Week {0} [CRITICAL ALERT]: Equipment malfunction detected! Nitrate spiked and stress occurred." wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "Turnover & Flow: 32.9x | Rating: Exemplary" wide
        $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "C | Alk 8.6 dKH | Ca 425 ppm | Phase: Pristine" wide
        $s6 = "Dynamic Reef Cross-Section & Sump Ecosystem" wide
        $s7 = "Turnover & Flow: {0:F1}x | Rating: {1}" wide
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Week 0: Aquarium baseline re-initialized." wide
        $s10 = "Saltwater Aquarium - Reef Section & Sump Station" wide
        $s11 = "Amphiprion ocellaris, Zebrasoma flavescens" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 5153792 and 4 of them
}

rule Sightlines_dotnet_typelib_guid_47884ce1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-47884ce1"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-47884ce1"
        family = ""
        hash = "07542948284356edd464a42312bcb8d55c6c6b9ab4920055d8aa62d229f6f857"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-47884ce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<Colombier.FormAccueil+SignalDrivenExtractor+<ScanPixels>d__1" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s5 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s6 = "System.Collections.Generic.IEnumerator<System.Byte>.Current" ascii
        $s7 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s8 = "Aucun rapport disponible. Lancez d'abord la simulation de la prairie." wide
        $s9 = " une grande part du foin : fiez-vous mieux " wide
        $s10 = "cision, avec quelques compromis entre qualit" wide
        $s11 = "cision moyenne : revoyez la date de coupe ou la dur" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1605632 and 12 of them
}

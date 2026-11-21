rule Sightlines_dotnet_typelib_guid_0889b765_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-0889b765"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-0889b765"
        family = ""
        hash = "20386c27f8146f786985f6fa778fbb40259280ce420273d27754423d83326637"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-0889b765.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".ResearchStation.DeckForm+<ReadPixelBytes>d__14" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Voyage XML structure conforms 100% to ResearchVesselStation.xsd schema rules." wide
        $s5 = "http://tempuri.org/ResearchVesselStation.xsd" wide
        $s6 = "Comma-delimited planned depths in meters (e.g. 10, 50, 100)" wide
        $s7 = " Wet Chemistry / Salinometer Lab:  {0:F0} m" wide
        $s8 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s9 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s10 = "Samples Collected (Water, Plankton, Core):" wide
        $s11 = "ResearchVesselStation.xsd file not found in executable directory." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2752512 and 12 of them
}

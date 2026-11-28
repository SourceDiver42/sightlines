rule Sightlines_contacted_78fd415e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-78fd415e"
        date = "2026-11-23"
        campaign = "contacted-78fd415e"
        family = ""
        hash = "7cc2d01bd7e3f446f8707049e464f20a36aa19d9c50b04e944f51dc03598ebd1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-78fd415e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<PrivateImplementationDetails>{869827A8-29D1-478E-B314-48676C61CBC2}" ascii
        $s1 = "<PrivateImplementationDetails>{D4933F01-4742-407D-982E-D47DDB340621}" ascii
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "D:\\Andrew\\AForge.NET\\trunk\\Sources\\Video.DirectShow\\obj\\Release\\AForge.Video.DirectShow.pdb" ascii
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "D:\\Andrew\\AForge.NET\\trunk\\Sources\\Video\\obj\\Release\\AForge.Video.pdb" ascii
        $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s7 = "D:\\Andrew\\AForge.NET\\trunk\\Sources\\Core\\obj\\Release\\AForge.pdb" ascii
        $s8 = "2No longer supported. Use AverageFrameRate instead." ascii
        $s9 = "Unable to retrieve video device capabilities. This video device requires a larger VideoStreamConfigC" wide
        $s10 = "AForge.Video.DirectShow.VideoCaptureDeviceForm.resources" ascii
        $s11 = "GetPinCapabilitiesAndConfigureSizeAndRate" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10829234 and 12 of them
}

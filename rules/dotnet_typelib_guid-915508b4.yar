rule Sightlines_dotnet_typelib_guid_915508b4_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-915508b4"
        date = "2026-10-30"
        campaign = "dotnet_typelib_guid-915508b4"
        family = "formbook"
        hash = "2eb57ebf4413f5ecc483cb4b186b8c888329a7f398b7b3d8253805d05e4e95ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-915508b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "VALIDATION SUCCESS: XML strictly complies with HillGatherSchema.xsd!" wide
        $s1 = " - CRITICAL BREAK-BACK: Flighty ewes bolted past dogs into Raven Gill!" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = " - RE-SWEEP EXECUTED: Shepherds and dogs turned back to head gullies." wide
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "(HillGather.HillForm+<ReadPixelBytes>d__8" ascii
        $s6 = "ALERT: Break-back detected into Raven Gill gully!" wide
        $s7 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s8 = "Estimated Stray / Break-Back Index: Moderate (34%)" wide
        $s9 = "06:00 AM - Gather party departs base fell. Ridge team climbing into position." wide
        $s10 = "18:00 PM - Daylight exhausted! Gather called to a halt for safety." wide
        $s11 = "Gather Team - Shepherds, Dogs & Equipment" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1590272 and 12 of them
}

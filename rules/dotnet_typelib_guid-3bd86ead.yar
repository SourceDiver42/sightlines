rule Sightlines_dotnet_typelib_guid_3bd86ead_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-3bd86ead"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-3bd86ead"
        family = ""
        hash = "50e6700881ce6280d7d69faee5b3074d562825b5d08bd44bdbae8f44759b359f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-3bd86ead.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[{0:HH:mm}] SCORCH WARNING! Flat iron scorched garment in {1} order!" wide
        $s1 = "[{0:HH:mm}] TEAR ALERT! Heavy wringer roll pinched fabric in {1} bundle!" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "[{0:HH:mm}] Wet air! Drying delay on racks due to weather & poor ventilation." wide
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "Victorian Plant Active | Steam: Rising | Workers: Moving Bundles | Pulley Racks: Operational" wide
        $s6 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s7 = "Daily Operations - Live Victorian Station Workflow & Risk Tracking" wide
        $s8 = "Delivery Success Rate : {0:0.0}% on schedule" wide
        $s9 = "Customer Orders - Laundry Type Mix & Logistics" wide
        $s10 = "Steam Laundry - Victorian Washhouse Plan" wide
        $s11 = "Bottleneck Identified : {0} (Queue depth: {1})" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2001920 and 12 of them
}

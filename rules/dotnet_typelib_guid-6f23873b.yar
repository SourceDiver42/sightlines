rule Sightlines_dotnet_typelib_guid_6f23873b_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-6f23873b"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-6f23873b"
        family = "formbook"
        hash = "1cb8c2d93e713f0f4855462bb8a7e12392e29989f0833413e7c6b68eb251eccd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-6f23873b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Report exported successfully to XML format validated against TramDepotSchema.xsd:" wide
        $s3 = "Day Form - Live Operational Run, Passenger Loadings, Bunching & Breakdowns" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Report Form - Journeys Operated, Headway Adherence, Availability & Reliability Rating" wide
        $s6 = "Fan Roads Stabling | Pit Road (Guva) Inspection | Street Route Loop | Stop Dwell | Night Return Orde" wide
        $s7 = "Schedule Form - Route Length, Stop Dwell, Headway Target & Crew Pattern" wide
        $s8 = "Route Network Plan : {0:F1} km, {1} Dukkana Stations" wide
        $s9 = "Depot Capacity     : {0} Fan Roads (Stabling), Pit Road Status: {1}" wide
        $s10 = "DAY FORM (YOMA RUN) - LIVE TIMELINE, BUNCHING & FAULTS" wide
        $s11 = "   * Bunching Incidents (Lkhitsa): {0} detected along corridor" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7625728 and 12 of them
}

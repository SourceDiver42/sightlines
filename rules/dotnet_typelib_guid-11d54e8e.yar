rule Sightlines_dotnet_typelib_guid_11d54e8e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-11d54e8e"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-11d54e8e"
        family = ""
        hash = "030a80b744cb7664d456d1a9590cc4bd1f115dbaec40578c1cf137ecd81e932e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-11d54e8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Docking Operation Rating: EXCELLENT (Grade A - Fully Compliant)" wide
        $s1 = "Ballast Tank Count: {0} | Combined Pump Capacity: {1} m3/hr" wide
        $s2 = "Block Loading Evenness: 98.4% balanced ({0:0.0} kN/m mean contact load)" wide
        $s3 = "Docking Operation Rating: ACCEPTABLE (Grade B - Monitoring Required)" wide
        $s4 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s5 = "Docking Operation Rating: EXCELLENT (Grade A)" wide
        $s6 = "Dry Dock Dimensions: Length={0} m, Pontoon Width={1} m, Wing Wall Height={2} m" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "Kile d'Shwita w'Shlama (Dock Trim, List & Stability Gauges)" wide
        $s9 = "Vessel Docked Status: OPERATION IN PROGRESS / SUBMERGED" wide
        $s10 = "Dukhra d'Shqala d'Nafqa (Docking Operation Report)" wide
        $s11 = "Pumping Time: {0:0.1} min | Estimated Generator Fuel: {1:0.1} Litres" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1955840 and 12 of them
}

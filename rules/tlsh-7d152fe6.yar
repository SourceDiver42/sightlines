rule Sightlines_tlsh_7d152fe6_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7d152fe6"
        date = "2026-11-06"
        campaign = "tlsh-7d152fe6"
        family = "agenttesla"
        hash = "0f11c24041a20cbec51c94030ef9e0fcfc2c97c8e759b11d40e9fca171193993"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7d152fe6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3GrandHotelKitchen.KitchenForm+<ReadPixelBytes>d__18" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Report exported successfully conforming to CulinaSchema.xsd:" wide
        $s5 = "TOTAL BRIGADE: {0} CHEFS | MISE EN PLACE: {1}%" wide
        $s6 = "<TempusTransactumSecunda>k__BackingField" ascii
        $s7 = "<DocketsPerMinutaFluxus>k__BackingField" ascii
        $s8 = "Menu blueprint and covers booking synchronized successfully." wide
        $s9 = "The value for column 'fg' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'd' in table 'DataTable1' is DBNull." wide
        $s11 = "Dishwashing Operation (Plonge Throughput)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1888256 and 12 of them
}

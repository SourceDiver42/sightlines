rule Sightlines_dotnet_typelib_guid_5201ba0c_snakekeylogger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5201ba0c"
        date = "2026-10-15"
        campaign = "dotnet_typelib_guid-5201ba0c"
        family = "snakekeylogger"
        hash = "66d3101e3b2207acdbdd9d0c14a1c3ea064e14a771705d8a4583faecaba98544"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5201ba0c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "<NombrePoidsLourdsServis>k__BackingField" ascii
        $s4 = "BilanAireService_{0:yyyyMMdd_HHmmss}.xml" wide
        $s5 = "<VolumeCarburantVenduLitres>k__BackingField" ascii
        $s6 = "<MettreAJourStatistiquesOccupation>b__64_0" ascii
        $s7 = "<MettreAJourStatistiquesOccupation>b__64_1" ascii
        $s8 = "<LitresCarburantDemandes>k__BackingField" ascii
        $s9 = "<ChiffreAffairesCarburant>k__BackingField" ascii
        $s10 = "<PlacesPoidsLourdsOccupees>k__BackingField" ascii
        $s11 = "<DureeMoyenneSejourSecondes>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1720320 and 12 of them
}

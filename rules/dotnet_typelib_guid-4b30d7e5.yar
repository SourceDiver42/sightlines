rule Sightlines_dotnet_typelib_guid_4b30d7e5_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b30d7e5"
        date = "2026-11-10"
        campaign = "dotnet_typelib_guid-4b30d7e5"
        family = "agenttesla"
        hash = "1e15d3711579966e16daf57d28f4948d2828b940c22de252a9c496f46cb2ce20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b30d7e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Campanae Hung Dead | Clappers Drawn by Wires | Baton Clavier | Louvres Open" wide
        $s4 = "Acta relatio prospere exportata sunt secundum CarillonSchema.xsd!" wide
        $s5 = "<CarillonneurBatonAngulus>k__BackingField" ascii
        $s6 = "Nexus Linkage Vitia (Slack Defectus): 0" wide
        $s7 = "Notae Purae: {0}  |  Dynamica Vitiosa: {1}" wide
        $s8 = "Choralis Sancti Rombout (Toccata Carillonis)" wide
        $s9 = "Campanarum harmonia fideliter servata est. Transmissionis nexus recte se habent nec ullae magnae cla" wide
        $s10 = "http://tempuri.org/CarillonSchema.xsd" wide
        $s11 = "<CarillonneurBrachiumY>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7351296 and 12 of them
}

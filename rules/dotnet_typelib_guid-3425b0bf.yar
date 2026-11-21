rule Sightlines_dotnet_typelib_guid_3425b0bf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-3425b0bf"
        date = "2026-11-18"
        campaign = "dotnet_typelib_guid-3425b0bf"
        family = ""
        hash = "4460fafd3de774d00defa0c094e0ef221de7eba72b49b75c183f6bb83a3d4898"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-3425b0bf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GYOCHAJI JEONGJI: Seonro Bool-ilchi Jeomgeom Jung... ({0:F0}cho Namum)" wide
        $s1 = "GYEONGGO: POKJU BALSAENG! (RUNAWAY DETECTED) - Geup-bureikeu Piryo!" wide
        $s2 = "UNHAENG WALLYO: Hwacha Hagan Dochak. Sae Set-eul Chulbal Sikiseyo." wide
        $s3 = "DAEGI JUNG: Set Chulbal Buton-eul Nuleumyeon Unhaeng-i Sijakdoemnida." wide
        $s4 = "UNHAENG JUNG: Naerim Hwacha Idong - Deureom Bureikeu: {0}%" wide
        $s5 = "The value for column 'FEUAHJSNI' in table 'DataTable1' is DBNull." wide
        $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s7 = "ILGAN UNHAENG GYODAE (Daily Shifts Monitor)" wide
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "The value for column 'faujhineiwquJHBF' in table 'DataTable1' is DBNull." wide
        $s10 = "Bureikeu Ha Rope Sokdo: {0:F2} m/s (Brake {1:F0}%)" wide
        $s11 = "The value for column 'dfnijvhujweiknf' in table 'DataTable1' is DBNull." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1709056 and 12 of them
}

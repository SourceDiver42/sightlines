rule Sightlines_imphash_d12d2f96_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d12d2f96"
        date = "2026-11-15"
        campaign = "imphash-d12d2f96"
        family = ""
        hash = "213a2ed1d5130ce40b5d3b8495fd41d9841c844da1116fd3a2b4eab85259c20c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d12d2f96.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FT_Get_CID_Registry_Ordering_Supplement" ascii
        $s1 = "%!PS-Adobe-3.0 Resource-CIDFont" ascii
        $s2 = "FT_Get_CID_Is_Internally_CID_Keyed" ascii
        $s3 = "FT_Face_GetCharVariantIsDefault" ascii
        $s4 = "FT_Library_SetLcdFilterWeights" ascii
        $s5 = "FT_Palette_Set_Foreground_Color" ascii
        $s6 = "FT_Get_Var_Design_Coordinates" ascii
        $s7 = "FT_Set_Var_Design_Coordinates" ascii
        $s8 = "FT_Get_Default_Named_Instance" ascii
        $s9 = "FT_Get_Var_Blend_Coordinates" ascii
        $s10 = "FT_Set_Var_Blend_Coordinates" ascii
        $s11 = "FT_Set_MM_Design_Coordinates" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1122640 and 12 of them
}

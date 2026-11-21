rule Sightlines_imphash_c0dd6add_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c0dd6add"
        date = "2026-11-15"
        campaign = "imphash-c0dd6add"
        family = ""
        hash = "3b99eb724cbbc35da1c158cc68d94b65095eaa4c772d9a1ce86678c9f07cfb72"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c0dd6add.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0Eclipse Foundation, Inc" wide
        $s1 = "OpenJDK Platform binary" wide
        $s2 = "http://www.eclipse.org/0" ascii
        $s3 = "__jsvml_hypotf16_ha_z0" ascii
        $s4 = "__jsvml_expm1f16_ha_z0" ascii
        $s5 = "__jsvml_log1pf16_ha_z0" ascii
        $s6 = "__jsvml_atan2f16_ha_z0" ascii
        $s7 = "__jsvml_cbrtf16_ha_z0" ascii
        $s8 = "__jsvml_log10f16_ha_z0" ascii
        $s9 = "__jsvml_log10f4_ha_e9" ascii
        $s10 = "__jsvml_log10f4_ha_ex" ascii
        $s11 = "__jsvml_log10f8_ha_e9" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1740112 and 12 of them
}

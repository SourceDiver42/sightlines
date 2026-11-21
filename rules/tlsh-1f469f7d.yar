rule Sightlines_tlsh_1f469f7d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1f469f7d"
        date = "2026-11-16"
        campaign = "tlsh-1f469f7d"
        family = ""
        hash = "08508c6cffa68f9f40f28a74333f8559d64aa67efb50b9ee05d25d13bed0877d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1f469f7d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "::res/drawable-xxxhdpi/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s1 = "::res/drawable-xxxhdpi/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
        $s2 = ",,res/color-v31/m3_dynamic_hint_foreground.xml" ascii
        $s3 = "::res/drawable-xxhdpi/abc_menu_hardkey_panel_mtrl_mult.9.png" ascii
        $s4 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant24.xml" ascii
        $s5 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant87.xml" ascii
        $s6 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant92.xml" ascii
        $s7 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant94.xml" ascii
        $s8 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant96.xml" ascii
        $s9 = "::res/color-v31/m3_ref_palette_dynamic_neutral_variant98.xml" ascii
        $s10 = "++res/layout-sw600dp/mtrl_layout_snackbar.xml" ascii
        $s11 = ";;res/drawable-xxhdpi/abc_cab_background_top_mtrl_alpha.9.png" ascii
    condition:
        filesize < 41335588 and 12 of them
}

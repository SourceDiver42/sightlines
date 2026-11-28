rule Sightlines_tlsh_16e6eac9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-16e6eac9"
        date = "2026-11-18"
        campaign = "tlsh-16e6eac9"
        family = ""
        hash = "088c7c4c816fab5fb170b92e635d2640ee98da18cb971e7617b80853385faf98"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-16e6eac9.json"
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
        filesize < 24534454 and 12 of them
}

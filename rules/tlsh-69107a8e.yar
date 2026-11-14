rule Sightlines_tlsh_69107a8e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-69107a8e"
        date = "2026-11-13"
        campaign = "tlsh-69107a8e"
        family = ""
        hash = "3637e3b4402c935185c62258fa8e3718184470f92467d3cc9fc119fec2752606"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-69107a8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "::res/drawable-xxxhdpi/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s1 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" ascii
        $s2 = "::res/drawable-xxxhdpi/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
        $s3 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" ascii
        $s4 = ">>Widget.Material3.TextInputLayout.FilledBox.ExposedDropdownMenu" ascii
        $s5 = "66RtlOverlay.Widget.AppCompat.PopupMenuItem.SubmenuArrow" ascii
        $s6 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" ascii
        $s7 = "<<Widget.MaterialComponents.TimePicker.Display.TextInputLayout" ascii
        $s8 = ",,res/color-v31/m3_dynamic_hint_foreground.xml" ascii
        $s9 = "GGWidget.MaterialComponents.TextInputLayout.FilledBox.ExposedDropdownMenu" ascii
        $s10 = ";;ThemeOverlay.Material3.ExtendedFloatingActionButton.Surface" ascii
        $s11 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" ascii
    condition:
        filesize < 14973774 and 12 of them
}

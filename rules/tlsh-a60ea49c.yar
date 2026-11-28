rule Sightlines_tlsh_a60ea49c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a60ea49c"
        date = "2026-11-19"
        campaign = "tlsh-a60ea49c"
        family = ""
        hash = "2f6f019ce846f9b95ec6234723373e6147d9183bf362af0f898d3ea75d72edbf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a60ea49c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" ascii
        $s1 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" ascii
        $s2 = ">>Widget.Material3.TextInputLayout.FilledBox.ExposedDropdownMenu" ascii
        $s3 = "66RtlOverlay.Widget.AppCompat.PopupMenuItem.SubmenuArrow" ascii
        $s4 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" ascii
        $s5 = "<<Widget.MaterialComponents.TimePicker.Display.TextInputLayout" ascii
        $s6 = ",,res/color-v31/m3_dynamic_hint_foreground.xml" ascii
        $s7 = "GGWidget.MaterialComponents.TextInputLayout.FilledBox.ExposedDropdownMenu" ascii
        $s8 = ";;ThemeOverlay.Material3.ExtendedFloatingActionButton.Surface" ascii
        $s9 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" ascii
        $s10 = "@@Widget.Material3.TextInputLayout.OutlinedBox.ExposedDropdownMenu" ascii
        $s11 = "00Widget.AppCompat.Light.ActionBar.TabView.Inverse" ascii
    condition:
        filesize < 14607086 and 12 of them
}

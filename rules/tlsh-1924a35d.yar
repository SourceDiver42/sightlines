rule Sightlines_tlsh_1924a35d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1924a35d"
        date = "2026-11-18"
        campaign = "tlsh-1924a35d"
        family = ""
        hash = "533a0cd10f6fae39753e03f58f031dbce5494e5f89866313927ba85f4538dc57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1924a35d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" ascii
        $s1 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" ascii
        $s2 = "66RtlOverlay.Widget.AppCompat.PopupMenuItem.SubmenuArrow" ascii
        $s3 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" ascii
        $s4 = "<<Widget.MaterialComponents.TimePicker.Display.TextInputLayout" ascii
        $s5 = "GGWidget.MaterialComponents.TextInputLayout.FilledBox.ExposedDropdownMenu" ascii
        $s6 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" ascii
        $s7 = "22RtlOverlay.Widget.AppCompat.PopupMenuItem.Shortcut" ascii
        $s8 = "<<Base.V14.Theme.MaterialComponents.Light.DarkActionBar.Bridge" ascii
        $s9 = "..RtlOverlay.Widget.AppCompat.SearchView.MagIcon" ascii
        $s10 = "JJ%1$s won't run without Google Play services, which are currently updating." ascii
        $s11 = "++RtlOverlay.Widget.AppCompat.Search.DropDown" ascii
    condition:
        filesize < 15547664 and 12 of them
}

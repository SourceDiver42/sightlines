rule Sightlines_tlsh_5b8892bb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b8892bb"
        date = "2026-11-20"
        campaign = "tlsh-5b8892bb"
        family = ""
        hash = "19cbb79dabd98b893fdfb56aa6c053abad9bb6c1e99b76f70daae9cfad2bfbe4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b8892bb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon2" ascii
        $s1 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Query" ascii
        $s2 = "66RtlOverlay.Widget.AppCompat.PopupMenuItem.SubmenuArrow" ascii
        $s3 = "00RtlOverlay.Widget.AppCompat.Search.DropDown.Text" ascii
        $s4 = "11RtlOverlay.Widget.AppCompat.Search.DropDown.Icon1" ascii
        $s5 = "00Widget.AppCompat.Light.ActionBar.TabView.Inverse" ascii
        $s6 = "22RtlUnderlay.Widget.AppCompat.ActionButton.Overflow" ascii
        $s7 = "22RtlOverlay.Widget.AppCompat.PopupMenuItem.Shortcut" ascii
        $s8 = "..RtlOverlay.Widget.AppCompat.SearchView.MagIcon" ascii
        $s9 = "++RtlOverlay.Widget.AppCompat.Search.DropDown" ascii
        $s10 = "**Base.DialogWindowTitleBackground.AppCompat" ascii
        $s11 = "00Widget.AppCompat.Light.ActionBar.TabText.Inverse" ascii
    condition:
        filesize < 6202582 and 12 of them
}

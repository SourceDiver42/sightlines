rule Sightlines_tlsh_3c7fc802_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c7fc802"
        date = "2026-11-19"
        campaign = "tlsh-3c7fc802"
        family = ""
        hash = "2e1b021a247886a21cecc493d5724c18defc021dc8d14184487bb769740e241e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c7fc802.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<<res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s1 = "==res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s2 = ";;res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s3 = "<<res/drawable-xxhdpi-v4/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
        $s4 = "==res/drawable-xxxhdpi-v4/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
        $s5 = "::res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s6 = "::res/drawable-mdpi-v4/abc_btn_switch_to_on_mtrl_00012.9.png" ascii
        $s7 = ";;res/drawable-xhdpi-v4/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
        $s8 = ";;res/drawable-xxhdpi-v4/abc_popup_background_mtrl_mult.9.png" ascii
        $s9 = "::res/drawable-xhdpi-v4/abc_popup_background_mtrl_mult.9.png" ascii
        $s10 = "res/drawable-v24/$ic_launcher_foreground__0.xmlPK" ascii
        $s11 = "::res/drawable-hdpi-v4/abc_btn_switch_to_on_mtrl_00001.9.png" ascii
    condition:
        filesize < 4664660 and 12 of them
}

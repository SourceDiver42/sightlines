rule Sightlines_imphash_dd990f2a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dd990f2a"
        date = "2026-11-16"
        campaign = "imphash-dd990f2a"
        family = ""
        hash = "40036a6623dad11b43ceafdb8f7ffa80ad67214d5cee2e49ac9fc1e4a0c005df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dd990f2a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "T2rmXbP-bNcxj3ljsjMKsV3dIt5-ScaZ9fRAcKrR1MLglaw16asnBaqyZ57zl-wWxhEUQPe94iOqOA_SeVDueIkiY84Ugvy-hyHu" ascii
        $s1 = "zJNStR7OXdxCDmUB4EXVnuFLcsheaublyuiantK9i6vT3sZNpI3OqXDtQmEYtBxPH1_GesiAugz2_x*8.1DkSP3A076EIHY4cz2c" ascii
        $s2 = "ebD45Nri9Ukllhm6cy3qcRr_5tVmRfrOFO6Ts9-jk672argZ4LdoVYUsz8dx0j1SAnJZ-kdBpLubDWmVRxoi6mf9FXThHPE2TX8E" ascii
        $s3 = "RPNwxo7fK5XmgdTl2YIO4Gtpr4roGaMnPzBWP9j6NlZVQpv.WBnUNNK1UdLsUgRK5hzQsDcKORtM_XHfLQyXC-yet7XDJ07FBWqo" ascii
        $s4 = "ZGKczq440byBTpN4NNborI8K-e64wj2EpyElw58mFdxNSDXoLVTjj1LKhnvgbbnHaRIIhsNRFtciWtMuFlh7y9gzrGOTQXYTBfmY" ascii
        $s5 = "x8D-vexV5z83neo_-U0kG_x-WrJMvb0BeYtRa-vCU4glnlqsDkPNDdj7P-cK5GoFKj2mche-wXIsTDZlP1O1XVr6ATEcIl6RifC0" ascii
        $s6 = "NQNPOpCYnnk39vc3DN6jwbcP1-os-euhOixoho1BT2Z\\QAy8SoJV4PSkkjflWHYZ8YLCwLD9UOZKDwgfAq5KN96fRWcMjOdm7vXe" ascii
        $s7 = " some than change little|8-LMzHQ5Xj7j-b0G06LPwFqRfS-SHvn94B2QRdVizAk-dPupH9WUNHJeJb1lC:\\Program File" ascii
        $s8 = "QU61ncAvb4LMtp0hcPq723ZBbgDuGNG14-AXPTPRRj1BEcrBn14_QYRoya5HOxDQe3l-VuqfimKRoDmjaq28ZHl7PX4EIdKZxrXj" ascii
        $s9 = "HM-be8BK3fdBmoGAg6Ryf_4LYMjOuls1Yzae8hXus2hHYl_WAoW9vcqZG4pE39si7sItH9MuUQ1NvubU-72NHS3Ov2DPZied0RZh" ascii
        $s10 = "1z_j8a2a4JTel-ptN30S0XO6yCEsgHPj-yb5EJRbL2oYvWR-D3p4Teyw3zOhCYxnaBjYwHzAhRX-Kqxr_-VMplnFOvkT3DmmsSd4" ascii
        $s11 = "LLFYI4iQZbkypc52N1l_ywp31G06fJ8-mzIk2LzXpOZUQPvT_DnZAMaTC03o7IwrU-aw5HoA38WYLXBViIiOSsSTXLr-RunfmHX-" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1211392 and 12 of them
}

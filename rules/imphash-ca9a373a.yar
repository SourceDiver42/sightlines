rule Sightlines_imphash_ca9a373a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ca9a373a"
        date = "2026-11-14"
        campaign = "imphash-ca9a373a"
        family = ""
        hash = "33aa8d4d4cf5af7b704032f923e6077a854c1fe78d3204ca0163fda47cc8d83a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ca9a373a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tlrpQnKycxgbPIl9HSkgxrYHUHN0cpDV-FiczWwBhsL_j4du2QNWWqm18EuK3ZoRc6MST1yNoHQNq8f6AJ6cY5cj5K7XRes6N4HX" ascii
        $s1 = "I_b7px3mrN.WU79OzOv_nFsk5F9k-ytaogzANr_MGHopPI5swEepxdxk8Of6MhK72.gT74nTBjs5L11B4hRgZj0LKgyD_AuQMe3x" ascii
        $s2 = "aBABhCI4RIAByg9zc0xArnElV2oO0NBUkiK-ta44mDzDo1s8nMeiPYcW1w91drfj6E9f5KLDgpI_Xg78.WdGCDZ945xd0XG5J1F6" ascii
        $s3 = "aRipLK6UfGK0q5gqkC81z9p6dOcdAsFCp8OztmtQ.M_69ndVtkANINcmh29vjbEGxnMqxZj-85UI9ay3eWgPw7eNxgg3XFJ.UpBm" ascii
        $s4 = "qCNoFA5M3kuKwc9.mWqyXBID1tUWzW8xZhzCV4E2luSzfTzpKMNg7c5m8HlM5r4azJ_1Cs.4kJOJZ2CFgsGhXj9xvmYZE-IOgAru" ascii
        $s5 = "N-847kOnEXD1hfAYQuUNC5s_9Fl-gm3mUe_xhZ60vk199oCjVZlx_lo6AtIrGDjmGqP8K2b71w24IxwuJMCCSeFi2end is will" ascii
        $s6 = "JYBtyvm6U4nPl4G4UPGOvdEQP5eqfwhOGcnnM2YUKsb-Puw8noasmuierthQLACZxdJu0iZLN_vGFInFpIVkCHhS_zZGNaNp18O7" ascii
        $s7 = "fryiescheaugy8M2-56jFC0ONLFG3s8bKCGeJDmH-y2wsHfejul7qIUQAurtBuo1SXjGcRKT4LbPO1CqR2G-52EXn_fzcj2WKYP1" ascii
        $s8 = "JpOrPCa0djOung-1xCuUWICU4ff_Nn9AH6u5ObBIecTKvlYA_9IiKojOcuLmA.4BWMqOPiRyvzRl2QUZKOFGwc2bGB7ax2jHH5Kt" ascii
        $s9 = "TcquQr9PdPAjodzkuIUl96VJpsWoV7a2hYMkBl6e3VsZDaqSohcLpjFG9CFFnkGX5gOMZRp\\ocjO3ItEas6jzeXDiaL8xEgBUgNw" ascii
        $s10 = "_Wf3Sc3s0kTMbBcyjpdXrl4BgOG30ZHmTvEVivn5S80UGn6bUkR0m6AwFusi83aqxiWA6NLVCSOLsPNqDB39F4h4GP7Wx5d2jECs" ascii
        $s11 = "YNXWq-gfWwITGS38CkC9qKE5Ir4BJ7QsD0PUT18tOct8Ko6_ZbPUA-Fwgles-CVTaH98VWy-9u2hF-8pXaeB_-jYVh1Z2aQ2-Nx" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1206272 and 12 of them
}

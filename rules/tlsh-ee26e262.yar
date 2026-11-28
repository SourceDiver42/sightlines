rule Sightlines_tlsh_ee26e262_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ee26e262"
        date = "2026-11-14"
        campaign = "tlsh-ee26e262"
        family = "coinminer"
        hash = "50aea28011e14de06a4b9d9d9911b7c7d06699a24a8760fffb08c8e5194ac2b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ee26e262.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(KHTML, like Gecko) Version/4.0 Mobile Safari/534.30 baiduboxapp/042_2.7.3_diordna_8021_027/IEWAUH_6" ascii
        $s1 = ".36 AliApp(DingTalk/4.5.11) com.alibaba.android.rimet/10487439 Channel/227200 language/zh-CN" ascii
        $s2 = "36 AliApp(DingTalk/4.5.8) com.alibaba.android.rimet/10380049 Channel/227200 language/zh-CN" ascii
        $s3 = "Gecko) Version/4.0 Chrome/53.0.2785.143 Crosswalk/24.53.595.0 XWEB/358 MMWEBSDK/23 Mobile Safari/537" ascii
        $s4 = ".36 MicroMessenger/6.7.2.1340(0x2607023A) NetType/4G Language/zh_CN)" ascii
        $s5 = "7.3.1340(0x26070332) NetType/4G Language/zh_CN Process/tools" ascii
        $s6 = "L, like Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/8.9 Mobile Safari/537.36" ascii
        $s7 = "L, like Gecko) Version/4.0 Chrome/57.0.2987.108 UCBrowser/12.1.4.994 Mobile Safari/537.36)" ascii
        $s8 = "Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/6.2 TBS/044353 Mobile Safari/537.36 MicroMessenge" ascii
        $s9 = "Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/6.2 TBS/044304 Mobile Safari/537.36 MicroMessenge" ascii
        $s10 = "L, like Gecko) Version/4.0 Chrome/57.0.2987.108 UCBrowser/11.9.4.974 UWS/2.13.1.48 Mobile Safari/537" ascii
        $s11 = "ecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/6.2 TBS/043906 Mobile Safari/537.36 MicroMessenger" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2406170 and 12 of them
}

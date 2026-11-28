rule Sightlines_tlsh_834dc48b_easyshell
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-834dc48b"
        date = "2026-11-26"
        campaign = "tlsh-834dc48b"
        family = "easyshell"
        hash = "06f77d29d7afaacc99d542f44b0ddc0324a42f278ee70f8610f3940ef8b393c1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-834dc48b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xenSYSTEMD_VIRTUALIZATIONhypervisorassembled large commandu;*3u,hu)#49!ES/8/BURI/" ascii
        $s1 = "[/sys/class/dmi/id/chassis_vendor8M5c7faXc4Q8NdXgpCRiIdhhCTyAujKw)9(??45.z6;4/\"`z34<;63>z54z;z" ascii
        $s2 = "ensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EXPORT_ONL" ascii
        $s3 = "ntscreenshottunnel/dev/nullINVOCATION_IDNOTIFY_SOCKET1<56>?(z 3*z?\"9??>)znz" ascii
        $s4 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s5 = "beacon uplink worker stoppedbeacon first POST timeoutzh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7text/html,ap" ascii
        $s6 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2locale-aC.UTF-8C.utf8en_US.UTF-8en_US.utf8zh_CN" ascii
        $s7 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s8 = "ELF!ES/FlowIfaFLinkCostRtmFAX25DlciVoidBootSiteHostMainInetAx25HashcallhashUtf8NlmFEDOMEADVutf8Texti" ascii
        $s9 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2() reached bottom => _URC_END_OF_STACK" ascii
        $s10 = "libunwind: unwind_phase2(ex_obj=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s11 = "libunwind: unwind_phase1(ex_obj=%p): __unw_step() reached bottom => _URC_END_OF_STACK" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 9264656 and 12 of them
}

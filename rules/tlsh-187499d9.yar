rule Sightlines_tlsh_187499d9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-187499d9"
        date = "2026-11-26"
        campaign = "tlsh-187499d9"
        family = "mirai"
        hash = "12115b4294e45874ff5135f9d0cf268820a4c3465a58614a90d22ebc2a957425"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-187499d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xenSYSTEMD_VIRTUALIZATIONhypervisorassembled large commandu;*3u,hu)#49!ES/8/BURI/" ascii
        $s1 = "[/sys/class/dmi/id/chassis_vendor8M5c7faXc4Q8NdXgpCRiIdhhCTyAujKw)9(??45.z6;4/\"`z34<;63>z54z;z" ascii
        $s2 = "ntscreenshottunnel/dev/nullINVOCATION_IDNOTIFY_SOCKET1<56>?(z 3*z?\"9??>)znz" ascii
        $s3 = "ECP_NISTZ256 for ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s4 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s5 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2locale-aC.UTF-8C.utf8en_US.UTF-8en_US.utf8zh_CN" ascii
        $s6 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s7 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2() reached bottom => _URC_END_OF_STACK" ascii
        $s8 = "libunwind: unwind_phase2(ex_obj=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s9 = "libunwind: unwind_phase1(ex_obj=%p): __unw_step() reached bottom => _URC_END_OF_STACK" ascii
        $s10 = "ELF!ES/FlowIfaFLinkCostRtmFAX25DlciVoidBootSiteHostMainInetAx25HashcallhashUtf8NlmFEDOMEADVutf8infoC" ascii
        $s11 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2 failed => _URC_FATAL_PHASE1_ERROR" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 7510304 and 12 of them
}

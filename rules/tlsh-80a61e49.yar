rule Sightlines_tlsh_80a61e49_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-80a61e49"
        date = "2026-11-26"
        campaign = "tlsh-80a61e49"
        family = "mirai"
        hash = "160d72279273ec84becdefd5cb03e30d17aceb7ee55b46251de6c4e84dc5ad45"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-80a61e49.json"
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
        $s8 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2() reached bottom => _URC_END_OF_STACK" ascii
        $s9 = "libunwind: unwind_phase2(ex_obj=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s10 = "+ punycode{}.llvm.::{closure#<>& *const ; ,_false{ {  = '..= | !nullstri8i16i32i64isizeu64usizef32f6" ascii
        $s11 = "libunwind: unwind_phase1(ex_obj=%p): __unw_step() reached bottom => _URC_END_OF_STACK" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 7538744 and 12 of them
}

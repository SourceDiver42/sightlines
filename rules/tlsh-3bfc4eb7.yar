rule Sightlines_tlsh_3bfc4eb7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3bfc4eb7"
        date = "2026-11-26"
        campaign = "tlsh-3bfc4eb7"
        family = "mirai"
        hash = "148ace31d1ed008796c9d3be335243e584bf1bdf53d1979a5168903a160f5a59"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3bfc4eb7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xenSYSTEMD_VIRTUALIZATIONhypervisorassembled large commandu;*3u,hu)#49!ES/8/BURI/" ascii
        $s1 = "[/sys/class/dmi/id/chassis_vendor8M5c7faXc4Q8NdXgpCRiIdhhCTyAujKw)9(??45.z6;4/\"`z34<;63>z54z;z" ascii
        $s2 = "ensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EXPORT_ONL" ascii
        $s3 = "(?i)\\s+\\((Linux|Windows|Darwin|Win|Mac|macOS)\\)\\s*$regexdispatch-1[!] ESCH chunk: target implant too" ascii
        $s4 = "SHA256 block transform for ARMv4/NEON/ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s5 = "SHA512 block transform for ARMv4/NEON, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s6 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s7 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2locale-aC.UTF-8C.utf8en_US.UTF-8en_US.utf8zh_CN" ascii
        $s8 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s9 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_END_OF_STACK" ascii
        $s10 = "libunwind: unwind_phase1(ex_ojb=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s11 = "libunwind: unwind_phase2(ex_ojb=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE2_ERROR" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 6703712 and 12 of them
}

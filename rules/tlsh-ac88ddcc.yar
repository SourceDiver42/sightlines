rule Sightlines_tlsh_ac88ddcc_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ac88ddcc"
        date = "2026-11-27"
        campaign = "tlsh-ac88ddcc"
        family = "coinminer"
        hash = "babd64048ff87611dfa55af74a882d62e4d6eb42e51fc0de495b74226bc90845"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ac88ddcc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s1 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s2 = "$host unreachableinteger overflow{invalid syntax}RSA_PKCS1_SHA384.debug_types.dwo" ascii
        $s3 = "Linker: LLD 22.1.6 (https://github.com/rust-lang/llvm-project.git dcc3606807c989700e0ac1cac18c31741b" ascii
        $s4 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2() reached bottom => _URC_END_OF_STACK" ascii
        $s5 = "libunwind: unwind_phase2(ex_obj=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s6 = "ithmX25519CertificateTypeNamedGroupECCurveTypeHpkeKemDHKEM_P256_HKDF_SHA256DHKEM_P384_HKDF_SHA384DHK" ascii
        $s7 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2 failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s8 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_CONTINUE_UNWIND" ascii
        $s9 = "libunwind: unwind_phase2_forced(ex_obj=%p): calling stop function with _UA_END_OF_STACK" ascii
        $s10 = "libunwind: unwind_phase2(ex_obj=%p): _URC_INSTALL_CONTEXT" ascii
        $s11 = "libunwind: unwind_phase2_forced(ex_obj=%p): __unw_get_proc_info failed => _URC_END_OF_STACK" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3304928 and 12 of them
}

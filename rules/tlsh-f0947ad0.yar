rule Sightlines_tlsh_f0947ad0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f0947ad0"
        date = "2026-11-27"
        campaign = "tlsh-f0947ad0"
        family = ""
        hash = "470583e43b58daf94941597753e61bf743809b0ea3d550036f639a386d0fb8b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f0947ad0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s1 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s2 = "Linker: LLD 22.1.6 (https://github.com/rust-lang/llvm-project.git dcc3606807c989700e0ac1cac18c31741b" ascii
        $s3 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2() reached bottom => _URC_END_OF_STACK" ascii
        $s4 = "libunwind: unwind_phase2(ex_obj=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s5 = "ithmX25519CertificateTypeNamedGroupECCurveTypeHpkeKemDHKEM_P256_HKDF_SHA256DHKEM_P384_HKDF_SHA384DHK" ascii
        $s6 = "PreambleUnixTimeTUNHELLOsalt_lenIpv4AddrNulError169.254.NoKeyLog" ascii
        $s7 = "libunwind: unwind_phase2(ex_obj=%p): __unw_step_stage2 failed => _URC_FATAL_PHASE1_ERROR" ascii
        $s8 = "libunwind: unwind_phase2_forced(ex_obj=%p): personality returned _URC_CONTINUE_UNWIND" ascii
        $s9 = "libunwind: unwind_phase2_forced(ex_obj=%p): calling stop function with _UA_END_OF_STACK" ascii
        $s10 = "libunwind: unwind_phase2(ex_obj=%p): _URC_INSTALL_CONTEXT" ascii
        $s11 = "libunwind: unwind_phase2_forced(ex_obj=%p): __unw_get_proc_info failed => _URC_END_OF_STACK" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 3157672 and 12 of them
}

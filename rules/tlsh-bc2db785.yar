rule Sightlines_tlsh_bc2db785_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc2db785"
        date = "2026-11-11"
        campaign = "tlsh-bc2db785"
        family = ""
        hash = "774f4828b8c589a78a624bb70354ed40888802c6dfc98510e15e8513b468caf5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc2db785.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_ZN12_GLOBAL__N_116itanium_demangle14PODSmallVectorIPNS0_4NodeELy32EE9push_backERKS3_" ascii
        $s1 = "_ZN12_GLOBAL__N_116itanium_demangle14PODSmallVectorIPNS1_IPNS0_4NodeELy8EEELy4EE9push_backERKS5_" ascii
        $s2 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s3 = "_ZN9libunwind12UnwindCursorINS_17LocalAddressSpaceENS_16Registers_x86_64EE14getInfoFromSEHEy" ascii
        $s4 = "_ZNK12_GLOBAL__N_116itanium_demangle8QualType19hasRHSComponentSlowERNS0_12OutputBufferE" ascii
        $s5 = "_ZN9libunwind12UnwindCursorINS_17LocalAddressSpaceENS_16Registers_x86_64EE15getFunctionNameEPcyPy" ascii
        $s6 = "_ZNK12_GLOBAL__N_116itanium_demangle19PointerToMemberType19hasRHSComponentSlowERNS0_12OutputBufferE" ascii
        $s7 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s8 = "_ZNK12_GLOBAL__N_116itanium_demangle8QualType15hasFunctionSlowERNS0_12OutputBufferE" ascii
        $s9 = "$cfgsj__ZN9libunwind12UnwindCursorINS_17LocalAddressSpaceENS_16Registers_x86_64EEC2EP13unw_context_t" ascii
        $s10 = "_ZNK12_GLOBAL__N_116itanium_demangle9ArrayType19hasRHSComponentSlowERNS0_12OutputBufferE" ascii
        $s11 = "_ZNK12_GLOBAL__N_116itanium_demangle13ParameterPack19hasRHSComponentSlowERNS0_12OutputBufferE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3337216 and 12 of them
}

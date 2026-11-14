rule Sightlines_imphash_4e047a03_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4e047a03"
        date = "2026-11-08"
        campaign = "imphash-4e047a03"
        family = ""
        hash = "1870fe31b0521653b7fa7a0dd2eace7e808f4646994c19033c5d7706b8872a9e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4e047a03.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GNU C23 16.2.0 -mtune=generic -march=x86-64 -g -O2 -O2 -O2 -fbuilding-libgcc -fno-stack-protector" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "X86_TUNE_SSE_PARTIAL_REG_FP_CONVERTS_DEPENDENCY" ascii
        $s3 = "X86_TUNE_FUSE_ALU_AND_BRANCH_RIP_RELATIVE" ascii
        $s4 = "X86_TUNE_SSE_PARTIAL_REG_CONVERTS_DEPENDENCY" ascii
        $s5 = "X86_TUNE_BRANCH_PREDICTION_HINTS_NOT_TAKEN" ascii
        $s6 = "X86_TUNE_BRANCH_PREDICTION_HINTS_TAKEN" ascii
        $s7 = "X86_TUNE_V2DF_REDUCTION_PREFER_HADDPD" ascii
        $s8 = "X86_TUNE_PREFER_KNOWN_REP_MOVSB_STOSB" ascii
        $s9 = "X86_TUNE_FUSE_ALU_AND_BRANCH_MEM_IMM" ascii
        $s10 = "X86_TUNE_AVOID_FALSE_DEP_FOR_TZCNT" ascii
        $s11 = "X86_TUNE_AVX512_MASKED_EPILOGUES" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1160290 and 12 of them
}

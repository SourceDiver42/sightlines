rule Sightlines_tlsh_07e70895_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-07e70895"
        date = "2026-11-27"
        campaign = "tlsh-07e70895"
        family = "coinminer"
        hash = "9cea866cd5d2b3611cf69d7ecfcc0c5a0280fc78218511f46e87c0a448ad095b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-07e70895.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned %d, _URC_FATAL_PHASE2_ERROR" ascii
        $s1 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_INSTALL_CONTEXT" ascii
        $s2 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_END_OF_STACK" ascii
        $s3 = "libunwind: unwind_phase2(ex_ojb=%p): __unw_get_proc_info failed => _URC_FATAL_PHASE2_ERROR" ascii
        $s4 = "libunwind: unwind_phase2_forced(ex_ojb=%p): personality returned _URC_CONTINUE_UNWIND" ascii
        $s5 = "libunwind: unwind_phase2_forced(ex_ojb=%p): calling stop function with _UA_END_OF_STACK" ascii
        $s6 = "libunwind: unwind_phase2(ex_ojb=%p): _URC_INSTALL_CONTEXT" ascii
        $s7 = "libunwind: unwind_phase2_forced(ex_ojb=%p): __unw_get_proc_info failed => _URC_END_OF_STACK" ascii
        $s8 = "libunwind: unwind_phase2(ex_ojb=%p): _URC_CONTINUE_UNWIND" ascii
        $s9 = "ug_str.dwo.debug_str_offsets.dwo.debug_tu_indexnote: run with `RUST_BACKTRACE=1` environment variabl" ascii
        $s10 = "libunwind: _Unwind_VRS_Set(context=%p, regclass=%d, reg=%d, rep=%d, value=0x%llX)" ascii
        $s11 = "libunwind: unwind_phase2_forced(ex_ojb=%p): start_ip=0x%x, func=%s, lsda=0x%x, personality=0x%x" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2927384 and 11 of them
}

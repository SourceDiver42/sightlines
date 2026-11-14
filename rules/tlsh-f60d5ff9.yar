rule Sightlines_tlsh_f60d5ff9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f60d5ff9"
        date = "2026-10-15"
        campaign = "tlsh-f60d5ff9"
        family = ""
        hash = "49e3cc11c904d158978479ad40b785d5d79845b0fc43b09122d3d6488c1dc300"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f60d5ff9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/usr/lib/libSystem.B.dylib" ascii
        $s2 = "/usr/lib/libc++.1.dylib" ascii
        $s3 = "@___stack_chk_guard" ascii
        $s4 = "@dyld_stub_binder" ascii
        $s5 = "@_mach_task_self_" ascii
        $s6 = "@___stack_chk_fail" ascii
        $s7 = "@_pthread_once" ascii
        $s8 = "__la_symbol_ptr" ascii
        $s9 = "__mod_init_func" ascii
        $s10 = "@___clear_cache" ascii
        $s11 = "__stub_helper" ascii
    condition:
        filesize < 2794080 and 12 of them
}

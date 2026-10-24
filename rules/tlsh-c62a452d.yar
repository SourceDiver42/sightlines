rule Sightlines_tlsh_c62a452d_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c62a452d"
        date = "2026-10-24"
        campaign = "tlsh-c62a452d"
        family = "amos"
        hash = "0c26434c9da255d1f717caa0e042f9b2c3b1088cc44892e3703edfb609b27b41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c62a452d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/usr/lib/libSystem.B.dylib" ascii
        $s2 = "/usr/lib/libc++.1.dylib" ascii
        $s3 = "@___cxa_guard_acquire" ascii
        $s4 = "@___cxa_guard_release" ascii
        $s5 = "@___stack_chk_guard" ascii
        $s6 = "@dyld_stub_binder" ascii
        $s7 = "@_mach_task_self_" ascii
        $s8 = "@___stack_chk_fail" ascii
        $s9 = "@_pthread_once" ascii
        $s10 = "__la_symbol_ptr" ascii
        $s11 = "__mod_init_func" ascii
    condition:
        filesize < 4796608 and 10 of them
}

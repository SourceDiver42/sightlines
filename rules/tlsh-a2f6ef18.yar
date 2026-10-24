rule Sightlines_tlsh_a2f6ef18_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2f6ef18"
        date = "2026-10-24"
        campaign = "tlsh-a2f6ef18"
        family = "amos"
        hash = "06a3833ccb61fe1dea39f628f1425524fd865c05a850aaf12da84bca23713292"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2f6ef18.json"
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
        filesize < 4729344 and 10 of them
}

rule Sightlines_tlsh_a1a761d8_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a1a761d8"
        date = "2026-11-06"
        campaign = "tlsh-a1a761d8"
        family = "amos"
        hash = "07f420f54347bacc8370353b2557d78fa681794bf67d0666670d374db278db34"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a1a761d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "/usr/lib/libc++.1.dylib" ascii
        $s2 = "@___cxa_guard_acquire" ascii
        $s3 = "@___cxa_guard_release" ascii
        $s4 = "@___stack_chk_guard" ascii
        $s5 = "@dyld_stub_binder" ascii
        $s6 = "@_mach_task_self_" ascii
        $s7 = "@___stack_chk_fail" ascii
        $s8 = "@_pthread_once" ascii
        $s9 = "__la_symbol_ptr" ascii
        $s10 = "__mod_init_func" ascii
        $s11 = "@___clear_cache" ascii
    condition:
        filesize < 4567392 and 10 of them
}

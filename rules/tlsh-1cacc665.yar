rule Sightlines_tlsh_1cacc665_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1cacc665"
        date = "2026-11-13"
        campaign = "tlsh-1cacc665"
        family = ""
        hash = "21eccb6c8992ec028d60f6bef6bf7d72facf23316cc4d15318f3767ed6ea83ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1cacc665.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "/usr/lib/libc++.1.dylib" ascii
        $s2 = "@___stack_chk_guard" ascii
        $s3 = "@dyld_stub_binder" ascii
        $s4 = "@_mach_task_self_" ascii
        $s5 = "@___stack_chk_fail" ascii
        $s6 = "@_pthread_once" ascii
        $s7 = "__la_symbol_ptr" ascii
        $s8 = "__mod_init_func" ascii
        $s9 = "@___clear_cache" ascii
        $s10 = "__stub_helper" ascii
        $s11 = "/usr/lib/dyld" ascii
    condition:
        filesize < 13061600 and 12 of them
}

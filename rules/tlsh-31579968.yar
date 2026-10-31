rule Sightlines_tlsh_31579968_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-31579968"
        date = "2026-10-30"
        campaign = "tlsh-31579968"
        family = ""
        hash = "59b27454b7007a23cad35f5fc1ed3366938688301d1b9682b5e54a48b48100a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-31579968.json"
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
        filesize < 4173984 and 12 of them
}

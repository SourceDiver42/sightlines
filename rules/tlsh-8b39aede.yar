rule Sightlines_tlsh_8b39aede_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8b39aede"
        date = "2026-11-09"
        campaign = "tlsh-8b39aede"
        family = "gafgyt"
        hash = "d2831e40b8b488dad4faf5ee3143a434be168e6abaf3b4048c32a9b023286f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8b39aede.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__stdio_mutex_initializer.3833" ascii
        $s1 = "_pthread_cleanup_pop_restore" ascii
        $s2 = "_pthread_cleanup_push_defer" ascii
        $s3 = "__pthread_initialize_minimal" ascii
        $s4 = "__GI___C_ctype_tolower_data" ascii
        $s5 = "__GI___C_ctype_toupper_data" ascii
        $s6 = "been_there_done_that.2792" ascii
        $s7 = "__pthread_mutex_trylock" ascii
        $s8 = "_stdio_openlist_del_count" ascii
        $s9 = "__heap_link_free_area_after" ascii
        $s10 = "_stdio_openlist_use_count" ascii
        $s11 = "__syscall_rt_sigaction.c" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

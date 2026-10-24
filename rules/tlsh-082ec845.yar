rule Sightlines_tlsh_082ec845_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-082ec845"
        date = "2026-10-22"
        campaign = "tlsh-082ec845"
        family = "mirai"
        hash = "894f8812b92a1b3fffff5ac2686c75db677180387edd41af6aea60c5ebf76e95"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-082ec845.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_pthread_sizeof_descr" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__linuxthreads_pthread_threads_max" ascii
        $s3 = "__GI_pthread_attr_getschedpolicy" ascii
        $s4 = "__GI_pthread_attr_setschedpolicy" ascii
        $s5 = "__pthread_wait_for_restart_signal" ascii
        $s6 = "__stdio_mutex_initializer.3862" ascii
        $s7 = "__GI_pthread_attr_getinheritsched" ascii
        $s8 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s9 = "__GI_pthread_attr_setinheritsched" ascii
        $s10 = "__pthread_kill_other_threads_np" ascii
        $s11 = "__GI_pthread_attr_getschedparam" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

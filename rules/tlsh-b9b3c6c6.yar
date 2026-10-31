rule Sightlines_tlsh_b9b3c6c6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9b3c6c6"
        date = "2026-10-28"
        campaign = "tlsh-b9b3c6c6"
        family = "mirai"
        hash = "1dfb43ea5771e8b518757c954fb5818a4d4a30042aa022bb1ce8ef3a837a79fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9b3c6c6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_initial_report_events" ascii
        $s1 = "__linuxthreads_pthread_threads_max" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__GI_pthread_attr_getinheritsched" ascii
        $s6 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s7 = "__GI_pthread_attr_setinheritsched" ascii
        $s8 = "__stdio_mutex_initializer.3833" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

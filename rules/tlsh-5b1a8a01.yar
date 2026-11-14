rule Sightlines_tlsh_5b1a8a01_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b1a8a01"
        date = "2026-11-07"
        campaign = "tlsh-5b1a8a01"
        family = "mirai"
        hash = "012005dfc612c9593ef433fbf1041409a1e9c6ee494df2488fee49aabecc578e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b1a8a01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__GI_pthread_attr_getinheritsched" ascii
        $s6 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s7 = "__GI_pthread_attr_setinheritsched" ascii
        $s8 = "__pthread_kill_other_threads_np" ascii
        $s9 = "__GI_pthread_attr_getschedparam" ascii
        $s10 = "__pthread_set_own_extricate_if" ascii
        $s11 = "__pthread_mutexattr_getkind_np" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

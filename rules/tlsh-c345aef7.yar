rule Sightlines_tlsh_c345aef7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c345aef7"
        date = "2026-11-02"
        campaign = "tlsh-c345aef7"
        family = "mirai"
        hash = "8de4290e52913fbb1540c95568eaf2bda15187bc9f9bc2ccd1858322f57267aa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c345aef7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "__linuxthreads_initial_report_events" ascii
        $s3 = "__linuxthreads_pthread_threads_max" ascii
        $s4 = "__GI_pthread_attr_getschedpolicy" ascii
        $s5 = "__GI_pthread_attr_setschedpolicy" ascii
        $s6 = "__pthread_wait_for_restart_signal" ascii
        $s7 = "__stdio_mutex_initializer.4280" ascii
        $s8 = "__GI_pthread_attr_getinheritsched" ascii
        $s9 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s10 = "__GI_pthread_attr_setinheritsched" ascii
        $s11 = "pthread_rwlockattr_getkind_np" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

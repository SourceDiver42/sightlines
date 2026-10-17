rule Sightlines_tlsh_52bd91c5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52bd91c5"
        date = "2026-10-15"
        campaign = "tlsh-52bd91c5"
        family = "mirai"
        hash = "9e983c4264e91c10e2afb873d7902e5986cd9eb8c39da4c71b76eef4eb58566e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52bd91c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "/etc/systemd/system/killer-helper.service" ascii
        $s4 = "__linuxthreads_initial_report_events" ascii
        $s5 = "Accept-Language: en-US,en;q=0.5" ascii
        $s6 = "__linuxthreads_pthread_threads_max" ascii
        $s7 = "Accept-Encoding: gzip, deflate" ascii
        $s8 = "__GI_pthread_attr_getschedpolicy" ascii
        $s9 = "__GI_pthread_attr_setschedpolicy" ascii
        $s10 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s11 = "__pthread_wait_for_restart_signal" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_3f7d1b0b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3f7d1b0b"
        date = "2026-11-04"
        campaign = "tlsh-3f7d1b0b"
        family = "mirai"
        hash = "18cdfe1c0cdd15ed7af29dcbe38e23853676ba7f7ec890cd0d344813f9f121a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3f7d1b0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept-Language: en-US,en;q=0.9" ascii
        $s1 = "Upgrade-Insecure-Requests: 1" ascii
        $s2 = "/var/spool/cron/crontabs/root" ascii
        $s3 = "Sec-Fetch-Mode: navigate" ascii
        $s4 = "Accept-Encoding: identity" ascii
        $s5 = "/var/lib/dbus/machine-id" ascii
        $s6 = "Sec-Fetch-Dest: document" ascii
        $s7 = "/proc/self/oom_score_adj" ascii
        $s8 = "Connection: keep-alive" ascii
        $s9 = "Sec-Fetch-Site: none" ascii
        $s10 = "Sec-Fetch-User: ?1" ascii
        $s11 = "/etc/machine-id" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

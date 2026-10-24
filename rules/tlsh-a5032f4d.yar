rule Sightlines_tlsh_a5032f4d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5032f4d"
        date = "2026-10-18"
        campaign = "tlsh-a5032f4d"
        family = "mirai"
        hash = "204e6d14591590ac52bc5c342ceb5ca87abdaa90d29b6e7cd1c84ebc291e7c5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5032f4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/proc/self/oom_score_adj" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "Restart=always" ascii
        $s4 = "[kworker/0:1]" ascii
        $s5 = "ExecStart=%s" ascii
        $s6 = "/etc/rc.local" ascii
        $s7 = "[Service]" ascii
        $s8 = "E8H;E0wrH" ascii
        $s9 = "tcpbypass" ascii
        $s10 = "AWAVAUATUL" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

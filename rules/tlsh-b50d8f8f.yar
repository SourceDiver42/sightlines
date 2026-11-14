rule Sightlines_tlsh_b50d8f8f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b50d8f8f"
        date = "2026-11-11"
        campaign = "tlsh-b50d8f8f"
        family = "mirai"
        hash = "0b2b1fd91ba1124070175edeba6d1b6d43ba33efed714535b8d14fb78da8628b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b50d8f8f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" ascii
        $s1 = "/usr/sbin/poweroff" ascii
        $s2 = "/usr/sbin/shutdown" ascii
        $s3 = "/usr/bin/poweroff" ascii
        $s4 = "/usr/bin/shutdown" ascii
        $s5 = "/usr/sbin/ftpget" ascii
        $s6 = "/usr/sbin/netstat" ascii
        $s7 = "/usr/sbin/busybox" ascii
        $s8 = "/usr/bin/ftpget" ascii
        $s9 = "/usr/sbin/reboot" ascii
        $s10 = "/usr/bin/busybox" ascii
        $s11 = "/usr/bin/netstat" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

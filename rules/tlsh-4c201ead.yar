rule Sightlines_tlsh_4c201ead_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4c201ead"
        date = "2026-11-19"
        campaign = "tlsh-4c201ead"
        family = "mirai"
        hash = "564dfe6ae748a660096d3606c8730c9111391faa7cd83d8caafb94090f16abfe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4c201ead.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ftpget -v -u anonymous -p anonymous -P 21 %s %s %s" ascii
        $s1 = "/usr/sbin/poweroff" ascii
        $s2 = "/usr/sbin/shutdown" ascii
        $s3 = "/usr/bin/poweroff" ascii
        $s4 = "/usr/bin/shutdown" ascii
        $s5 = "/usr/sbin/ftpget" ascii
        $s6 = "/usr/sbin/busybox" ascii
        $s7 = "/usr/sbin/netstat" ascii
        $s8 = "/usr/bin/ftpget" ascii
        $s9 = "/usr/sbin/reboot" ascii
        $s10 = "/usr/bin/busybox" ascii
        $s11 = "/usr/bin/netstat" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

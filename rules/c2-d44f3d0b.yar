rule Sightlines_c2_d44f3d0b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-d44f3d0b"
        date = "2026-11-24"
        campaign = "c2-d44f3d0b"
        family = "mirai"
        hash = "06d1ba7f32edddc876f34eb220edb3940643724185dffbceaf1d2f410a44c2d3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-d44f3d0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "X-GNOME-Autostart-enabled=true" ascii
        $s1 = "@reboot %s >/dev/null 2>&1" ascii
        $s2 = "/etc/profile.d/sysupd.sh" ascii
        $s3 = "%s/.config/systemd/user" ascii
        $s4 = "%s/.config/autostart" ascii
        $s5 = "After=network.target" ascii
        $s6 = "%s/.config/.sysupd" ascii
        $s7 = "/dev/misc/watchdog" ascii
        $s8 = "Description=sysupd" ascii
        $s9 = "/etc/cron.d/sysupd" ascii
        $s10 = "/etc/init.d/sysupd" ascii
        $s11 = "/etc/xdg/autostart" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

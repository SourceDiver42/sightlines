rule Sightlines_contacted_cde4fa48_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-cde4fa48"
        date = "2026-11-15"
        campaign = "contacted-cde4fa48"
        family = ""
        hash = "26a130b4d98c369ac5654549e475d57d17317b59a270d22582e03b1dad44deb7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-cde4fa48.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    start-stop-daemon --stop --pidfile \"$pidfile\" --exec \"$command\" --retry SIGTERM/15/SIGKILL/5" ascii
        $s1 = "    HEYIWEI_SERVICE=1 /usr/local/bin/Heyiwei" ascii
        $s2 = "# Short-Description: Heyiwei managed Linux device" ascii
        $s3 = "    start) HEYIWEI_SERVICE=1 \"$binary\" ;;" ascii
        $s4 = "# The release binary already forks, so use rc.common's daemon-compatible path." ascii
        $s5 = "    *) echo 'Usage: Heyiwei {start|stop|restart|status}' >&2; exit 2 ;;" ascii
        $s6 = "host=%.63s arch=%.31s kernel=%.63s uid=%lu" ascii
        $s7 = "description=\"Heyiwei managed Linux device\"" ascii
        $s8 = "Description=Heyiwei managed Linux device" ascii
        $s9 = "file replaced but directory sync failed; durability unconfirmed" ascii
        $s10 = "/etc/systemd/system/multi-user.target.wants/Heyiwei.service" ascii
        $s11 = "# Required-Start: $network $remote_fs" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

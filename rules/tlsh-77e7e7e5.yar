rule Sightlines_tlsh_77e7e7e5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-77e7e7e5"
        date = "2026-11-22"
        campaign = "tlsh-77e7e7e5"
        family = "mirai"
        hash = "11b8a87847eb99b358a8d2eef712167a277396a1da251e91147d67d3c75482df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-77e7e7e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (C-SKY Tools V3.10.7 uClibc-ng-1.0.29 Linux-4.9.56 abiv1 B20190605) 6.3.0" ascii
        $s1 = "    start-stop-daemon --stop --pidfile \"$pidfile\" --exec \"$command\" --retry SIGTERM/15/SIGKILL/5" ascii
        $s2 = "    HEYIWEI_SERVICE=1 /usr/local/bin/Heyiwei" ascii
        $s3 = "# Short-Description: Heyiwei managed Linux device" ascii
        $s4 = "    start) HEYIWEI_SERVICE=1 \"$binary\" ;;" ascii
        $s5 = "# The release binary already forks, so use rc.common's daemon-compatible path." ascii
        $s6 = "    *) echo 'Usage: Heyiwei {start|stop|restart|status}' >&2; exit 2 ;;" ascii
        $s7 = "host=%.63s arch=%.31s kernel=%.63s uid=%lu" ascii
        $s8 = "%s: '%s' is not an ELF executable for csky" ascii
        $s9 = "description=\"Heyiwei managed Linux device\"" ascii
        $s10 = "Description=Heyiwei managed Linux device" ascii
        $s11 = "file replaced but directory sync failed; durability unconfirmed" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

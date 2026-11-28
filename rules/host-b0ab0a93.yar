rule Sightlines_host_b0ab0a93_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-b0ab0a93"
        date = "2026-11-24"
        campaign = "host-b0ab0a93"
        family = "mirai"
        hash = "031ef92f0d33f16343acc3703c934522b54869d1bf512f9f01ac1aaf53e82e6d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-b0ab0a93.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "systemctl enable %s.service >/dev/null 2>&1 || true" ascii
        $s1 = "Looks like you are a honeypot, this tool was made by t.me/flylegit!" ascii
        $s2 = "http://94.154.43.120/iran.%s" ascii
        $s3 = "# Required-Start: $network" ascii
        $s4 = "/etc/systemd/system/%s.service" ascii
        $s5 = "Description=System Service" ascii
        $s6 = "# Default-Start:  2 3 4 5" ascii
        $s7 = "crontab -l 2>/dev/null" ascii
        $s8 = "Connection: keep-alive" ascii
        $s9 = "After=network.target" ascii
        $s10 = "Content-Length: 16" ascii
        $s11 = "### BEGIN INIT INFO" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

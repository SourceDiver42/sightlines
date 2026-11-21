rule Sightlines_tlsh_0b792b0a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0b792b0a"
        date = "2026-11-16"
        campaign = "tlsh-0b792b0a"
        family = "mirai"
        hash = "2ed4ad1d2d298895faa81e4cdc6420b0dd826c4ce5a5c71b7964af671a6fa55f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0b792b0a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "systemctl enable %s.service >/dev/null 2>&1 || true" ascii
        $s1 = "cannot create TLS data structures: ABORT" ascii
        $s2 = "cannot allocate memory in static TLS block" ascii
        $s3 = "FATAL: exception not rethrown" ascii
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

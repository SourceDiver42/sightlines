rule Sightlines_c2_ecf8bfe7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-ecf8bfe7"
        date = "2026-11-05"
        campaign = "c2-ecf8bfe7"
        family = "mirai"
        hash = "0978c48d03225651ac1df665352c4d5bd154905dd5b7672d0e7ba736882354fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-ecf8bfe7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/var/tmp/%s\\nRestart=on-failure\\nRestartSec=30\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/syst" ascii
        $s1 = "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=" ascii
        $s2 = "echo '0' > /proc/sys/kernel/pid_max 2>/dev/null" ascii
        $s3 = "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null" ascii
        $s4 = "find /tmp /var/tmp /dev/shm /root -name '*%s*' -delete 2>/dev/null" ascii
        $s5 = "chmod +x /var/tmp/%s /usr/lib/%s 2>/dev/null" ascii
        $s6 = "systemctl daemon-reload 2>/dev/null; systemctl enable %s 2>/dev/null" ascii
        $s7 = "rm -f /lib/systemd/system/%s.service 2>/dev/null" ascii
        $s8 = "systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null" ascii
        $s9 = "sed -i '/%s/d' /etc/rc.local 2>/dev/null" ascii
        $s10 = "rm -f /etc/systemd/system/%s.service 2>/dev/null" ascii
        $s11 = "chattr +i /var/tmp/%s 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

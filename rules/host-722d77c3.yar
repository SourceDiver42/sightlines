rule Sightlines_host_722d77c3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-722d77c3"
        date = "2026-10-22"
        campaign = "host-722d77c3"
        family = "mirai"
        hash = "073acd8059a1c492fcfe4bee8b5a6134003d85a4f30f5718a9a9c21d842d16e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-722d77c3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Embedded Telnet Server.*WARNING:.*authorized users only" ascii
        $s1 = "(crontab -l 2>/dev/null; printf '@reboot %s %s &\\n') | crontab - 2>/dev/null" ascii
        $s2 = "killall -9 httpd lighttpd boa goahead mini_httpd webs 2>/dev/null" ascii
        $s3 = "killall -9 .t .nttpd .sh4 dvrHelper yakuza .mi mozi satori .tsunami .hakai .owari mirai hajime .nipp" ascii
        $s4 = "/bin/busybox chmod 777 .f || chmod 777 .f; ./.f telnet; rm -f .f" ascii
        $s5 = "on macHelper .z .loaded zollard .chinaz .sh 2>/dev/null" ascii
        $s6 = "/bin/busybox cat /proc/self/exe || cat /proc/self/exe" ascii
        $s7 = "TELNET session now in ESTABLISHED state" ascii
        $s8 = "/bin/busybox cat /proc/cpuinfo || cat /proc/cpuinfo" ascii
        $s9 = "Ubee Interactive Corporation Telnet Server" ascii
        $s10 = "NetComm ADSL2\\S Wireless Router" ascii
        $s11 = "Copyright (c) 2010-2012 Hewle" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1838288 and 8 of them
}

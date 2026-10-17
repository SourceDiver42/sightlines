rule Sightlines_tlsh_379be63e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-379be63e"
        date = "2026-10-15"
        campaign = "tlsh-379be63e"
        family = "mirai"
        hash = "2f7be7bf192bb93d92147d306b1540f549d32d8df9b8d98394728f5f20416d2a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-379be63e.json"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

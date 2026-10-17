rule Sightlines_host_86230649_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-86230649"
        date = "2026-10-17"
        campaign = "host-86230649"
        family = "mirai"
        hash = "122e80c889c1d4f7b9f99abe635711b02aadf2d110447d2df18082458178f754"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-86230649.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "/etc/systemd/system/killer-helper.service" ascii
        $s4 = "Accept-Language: en-US,en;q=0.5" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s7 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s8 = "/usr/lib/systemd/.system-helper" ascii
        $s9 = "0.0.0.0 hybrid-analysis.com" ascii
        $s10 = "0.0.0.0 www.malwarebytes.com" ascii
        $s11 = "Description=System Helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

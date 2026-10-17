rule Sightlines_tlsh_51426235_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51426235"
        date = "2026-10-15"
        campaign = "tlsh-51426235"
        family = "mirai"
        hash = "0bb1e6a3be4fe5294ea2c5f1463f298a05e6deba4601c3fa64180859ee7d13c6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51426235.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "systemctl daemon-reload 2>/dev/null; systemctl enable killer-helper.service 2>/dev/null" ascii
        $s2 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s3 = "cannot create TLS data structures: ABORT" ascii
        $s4 = "cannot allocate memory in static TLS block" ascii
        $s5 = "/etc/systemd/system/killer-helper.service" ascii
        $s6 = "Accept-Language: en-US,en;q=0.5" ascii
        $s7 = "Invalid multibyte format string." ascii
        $s8 = "Accept-Encoding: gzip, deflate" ascii
        $s9 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s10 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s11 = "/usr/lib/systemd/.system-helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

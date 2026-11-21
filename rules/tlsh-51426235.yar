rule Sightlines_tlsh_51426235_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51426235"
        date = "2026-11-07"
        campaign = "tlsh-51426235"
        family = "mirai"
        hash = "0bb1e6a3be4fe5294ea2c5f1463f298a05e6deba4601c3fa64180859ee7d13c6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51426235.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s2 = "cannot create TLS data structures: ABORT" ascii
        $s3 = "cannot allocate memory in static TLS block" ascii
        $s4 = "/etc/systemd/system/killer-helper.service" ascii
        $s5 = "Accept-Language: en-US,en;q=0.5" ascii
        $s6 = "Invalid multibyte format string." ascii
        $s7 = "Accept-Encoding: gzip, deflate" ascii
        $s8 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s9 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s10 = "/usr/lib/systemd/.system-helper" ascii
        $s11 = "FFFFFFFFFFFFFcZZWFFFFFFFFFFFFYH[?cHEcFHWH[ZDE%OCZZZZ=FFFFXHFF_<<<<<<" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}

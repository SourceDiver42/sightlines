rule Sightlines_tlsh_65d7970d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-65d7970d"
        date = "2026-10-30"
        campaign = "tlsh-65d7970d"
        family = "mirai"
        hash = "153f4fedbeb1efa5ef23208c5bcfd2826f9f55c0811b795ca53d6af35f21b3d5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-65d7970d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/killer-helper.service" ascii
        $s3 = "Accept-Language: en-US,en;q=0.5" ascii
        $s4 = "Accept-Encoding: gzip, deflate" ascii
        $s5 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s6 = "PATH=/usr/sbin:/usr/bin:/sbin:/bin" ascii
        $s7 = "/usr/lib/systemd/.system-helper" ascii
        $s8 = "0.0.0.0 hybrid-analysis.com" ascii
        $s9 = "0.0.0.0 www.malwarebytes.com" ascii
        $s10 = "M(knN__vdso_clock_gettime" ascii
        $s11 = "Description=System Helper" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_a0e6fea8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a0e6fea8"
        date = "2026-10-23"
        campaign = "tlsh-a0e6fea8"
        family = "mirai"
        hash = "22fc6d79d77e513db7ec7f95fc27aed76a67779955109e0a17dd54f9a7b3ea8e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a0e6fea8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Required key not available" ascii
        $s1 = "Key was rejected by service" ascii
        $s2 = "__vdso_clock_gettime64" ascii
        $s3 = "Key has been revoked" ascii
        $s4 = "Key has expired" ascii
        $s5 = ".relro_padding" ascii
        $s6 = "Restart=always" ascii
        $s7 = "/proc/%d/stat" ascii
        $s8 = "ExecStart=%s" ascii
        $s9 = "/bin/busybox" ascii
        $s10 = "/proc/%d/exe" ascii
        $s11 = "Type=simple" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_38921d66_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-38921d66"
        date = "2026-10-15"
        campaign = "tlsh-38921d66"
        family = ""
        hash = "02bf8124a5351b11257ad7349562fa6be06d470e8f39e1c2ec26ef6d31017a16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-38921d66.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "__kernel_clock_gettime" ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "/usr/local/bin/bash" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "LINUX_2.6.39" ascii
        $s11 = "/usr/bin/bash" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

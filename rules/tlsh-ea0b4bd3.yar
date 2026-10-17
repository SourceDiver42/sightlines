rule Sightlines_tlsh_ea0b4bd3_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ea0b4bd3"
        date = "2026-10-15"
        campaign = "tlsh-ea0b4bd3"
        family = "mirai"
        hash = "6c246263128ea32057f1fbfb5293636e09d9cd11f5c60628756c7548bd3093bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ea0b4bd3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (Buildroot 2021.11-18033-g83947c7bb6) 14.3.0" ascii
        $s1 = "Required key not available" ascii
        $s2 = "Key was rejected by service" ascii
        $s3 = "__vdso_clock_gettime64" ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "/usr/local/bin/bash" ascii
        $s6 = "Key has expired" ascii
        $s7 = "/usr/bin/busybox" ascii
        $s8 = "/data/local/tmp" ascii
        $s9 = "/tmp/.Kdat_tmp" ascii
        $s10 = "/usr/bin/bash" ascii
        $s11 = "/usr/bin/sh" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

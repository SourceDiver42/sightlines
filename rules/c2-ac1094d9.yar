rule Sightlines_c2_ac1094d9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-ac1094d9"
        date = "2026-11-14"
        campaign = "c2-ac1094d9"
        family = "mirai"
        hash = "1e47415db891d0b6e939674640e81d8375dcf628a24753e2a86f89c09c51215e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-ac1094d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "clang version 18.1.6 (https://github.com/ziglang/zig-bootstrap 98bc6bf4fc4009888d33941daf6b600d20a42" ascii
        $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s3 = "wrgn39_dlob.hans_dir645_V1" ascii
        $s4 = "wrgac01_dlob.hans_dir865" ascii
        $s5 = "Required key not available" ascii
        $s6 = "Key was rejected by service" ascii
        $s7 = "3UJUh2VemEfUtesEchEC2d2e" ascii
        $s8 = "wapnd04cm_dkbs_dap3525" ascii
        $s9 = "wapnd03cm_dkbs_dap2555" ascii
        $s10 = "__vdso_clock_gettime64" ascii
        $s11 = "ManagementConsole2015" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

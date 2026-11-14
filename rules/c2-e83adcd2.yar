rule Sightlines_c2_e83adcd2_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-e83adcd2"
        date = "2026-11-09"
        campaign = "c2-e83adcd2"
        family = "mirai"
        hash = "1e47415db891d0b6e939674640e81d8375dcf628a24753e2a86f89c09c51215e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-e83adcd2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "clang version 18.1.6 (https://github.com/ziglang/zig-bootstrap 98bc6bf4fc4009888d33941daf6b600d20a42" ascii
        $s1 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s3 = "x86_64 ; chmod 777 x86_64 ; ./x86_64 fiberrt ;" ascii
        $s4 = "l ; chmod 777 mpsl ; ./mpsl fiberrt ;" ascii
        $s5 = "wrgn39_dlob.hans_dir645_V1" ascii
        $s6 = "wrgac01_dlob.hans_dir865" ascii
        $s7 = "Required key not available" ascii
        $s8 = "Key was rejected by service" ascii
        $s9 = "3UJUh2VemEfUtesEchEC2d2e" ascii
        $s10 = "wapnd04cm_dkbs_dap3525" ascii
        $s11 = "wapnd03cm_dkbs_dap2555" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_fcd3df0e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcd3df0e"
        date = "2026-11-18"
        campaign = "tlsh-fcd3df0e"
        family = "mirai"
        hash = "01dae93af638e17f975ba53ed4f69b2983d96dab32e2a45b4280eb03bfbbccb1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fcd3df0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ULT1M4T3-STY-CNC-CH4CH4-K3Y!2026/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = ",:HVVVVVVdt-0X+0X 0X-0x+0x 0x" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "__kernel_clock_gettime" ascii
        $s7 = "sec-ch-ua-platform" ascii
        $s8 = "expand 32-byte kg" ascii
        $s9 = "gzip, deflate, br" ascii
        $s10 = "/proc/self/status" ascii
        $s11 = "sec-ch-ua-mobile" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

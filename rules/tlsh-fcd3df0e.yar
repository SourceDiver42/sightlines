rule Sightlines_tlsh_fcd3df0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcd3df0e"
        date = "2026-10-23"
        campaign = "tlsh-fcd3df0e"
        family = ""
        hash = "3a713c5ce832c00a959f2603dd757e453c5b4b01b3d2f528ee4636db8c012777"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

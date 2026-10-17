rule Sightlines_host_7a6a071f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-7a6a071f"
        date = "2026-10-16"
        campaign = "host-7a6a071f"
        family = "mirai"
        hash = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-7a6a071f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Connection: keep-alive" ascii
        $s1 = "POST %s HTTP/1.1" ascii
        $s2 = "/proc/self/maps" ascii
        $s3 = "GET %s HTTP/1.1" ascii
        $s4 = "__cxa_atexit" ascii
        $s5 = "/index.php" ascii
        $s6 = "LD_PROFILE" ascii
        $s7 = "/usr/lib/" ascii
        $s8 = "LD_AUDIT" ascii
        $s9 = "LD_DEBUG" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2147280 and 10 of them
}

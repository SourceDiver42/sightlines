rule Sightlines_tlsh_daca68ea_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-daca68ea"
        date = "2026-11-22"
        campaign = "tlsh-daca68ea"
        family = "mirai"
        hash = "22e2123fdf57b365fb902b917321510a0a47e9e11587762c8c08d702a37325f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-daca68ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Required key not available" ascii
        $s1 = "Key was rejected by service" ascii
        $s2 = "__vdso_clock_gettime64" ascii
        $s3 = "Connection: keep-alive" ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "Key has expired" ascii
        $s6 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}

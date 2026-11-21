rule Sightlines_tlsh_a4c8d768_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4c8d768"
        date = "2026-11-13"
        campaign = "tlsh-a4c8d768"
        family = "mirai"
        hash = "19579840075efd5234e5087a170ba0d0fdb20d6c66608007756a8c95b00b9be8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4c8d768.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__vdso_clock_gettime64" ascii
        $s1 = "/run/systemd/system" ascii
        $s2 = ".gnu.attributes" ascii
        $s3 = ".MIPS.abiflags" ascii
        $s4 = "Type=forking" ascii
        $s5 = "[Service]" ascii
        $s6 = "/etc/rc.d" ascii
        $s7 = ".comment" ascii
        $s8 = ".rel.dyn" ascii
        $s9 = "/usr/bin" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

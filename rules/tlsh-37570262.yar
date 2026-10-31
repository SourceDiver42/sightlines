rule Sightlines_tlsh_37570262_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-37570262"
        date = "2026-10-25"
        campaign = "tlsh-37570262"
        family = ""
        hash = "085dc35f07a9b087da3a765ef388c04d751e01885a9d64fae7b14167ee0cccb7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-37570262.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "__libc_start_main@@GLIBC_2.2.5" ascii
        $s2 = "gethostbyname@@GLIBC_2.2.5" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "__frame_dummy_init_array_entry" ascii
        $s6 = "_ITM_registerTMCloneTable" ascii
        $s7 = "setsockopt@@GLIBC_2.2.5" ascii
        $s8 = "inet_addr@@GLIBC_2.2.5" ascii
        $s9 = "__environ@@GLIBC_2.2.5" ascii
        $s10 = "realpath@@GLIBC_2.3" ascii
        $s11 = "connect@@GLIBC_2.2.5" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

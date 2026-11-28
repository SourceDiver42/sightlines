rule Sightlines_tlsh_c53dc5d5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c53dc5d5"
        date = "2026-11-27"
        campaign = "tlsh-c53dc5d5"
        family = ""
        hash = "0149ed565f55195e2a611d5b3576b01b8f5a8b6acb7162e71cd659034f45b105"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c53dc5d5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "__libc_start_main@@GLIBC_2.0" ascii
        $s2 = "gethostbyname@@GLIBC_2.0" ascii
        $s3 = "_ITM_deregisterTMCloneTable" ascii
        $s4 = "__frame_dummy_init_array_entry" ascii
        $s5 = "_ITM_registerTMCloneTable" ascii
        $s6 = "setsockopt@@GLIBC_2.0" ascii
        $s7 = "__i686.get_pc_thunk.bx" ascii
        $s8 = "inet_addr@@GLIBC_2.0" ascii
        $s9 = "__environ@@GLIBC_2.0" ascii
        $s10 = "realpath@@GLIBC_2.3" ascii
        $s11 = "sprintf@@GLIBC_2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

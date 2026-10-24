rule Sightlines_tlsh_685a7e67_snowlight
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-685a7e67"
        date = "2026-10-21"
        campaign = "tlsh-685a7e67"
        family = "snowlight"
        hash = "b10b0a0544ca487803814a5570cc32b337a9e30a9abcd7984534c30070c4763b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-685a7e67.json"
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
        $s11 = "deregister_tm_clones" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

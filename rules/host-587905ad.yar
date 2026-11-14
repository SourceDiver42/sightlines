rule Sightlines_host_587905ad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-587905ad"
        date = "2026-11-10"
        campaign = "host-587905ad"
        family = ""
        hash = "1175119ef24f85cdc0b16380f6571eeb160808698e3d7b16545ad622dc247e32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-587905ad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "__frame_dummy_init_array_entry" ascii
        $s3 = "_ITM_registerTMCloneTable" ascii
        $s4 = "deregister_tm_clones" ascii
        $s5 = "_GLOBAL_OFFSET_TABLE_" ascii
        $s6 = "__libc_start_main" ascii
        $s7 = "__init_array_start" ascii
        $s8 = "/tmp/log_de.log" ascii
        $s9 = "__init_array_end" ascii
        $s10 = ".gnu.version_r" ascii
        $s11 = "_IO_stdin_used" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_host_0a48ca2f_snowlight
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-0a48ca2f"
        date = "2026-11-27"
        campaign = "host-0a48ca2f"
        family = "snowlight"
        hash = "00ace3c505679d5da5e3035c42654d3d7b7fafd47de0ae251a0d758a8be27eaa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-0a48ca2f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "__frame_dummy_init_array_entry" ascii
        $s3 = "_ITM_registerTMCloneTable" ascii
        $s4 = "realpath@@GLIBC_2.3" ascii
        $s5 = "deregister_tm_clones" ascii
        $s6 = "_GLOBAL_OFFSET_TABLE_" ascii
        $s7 = "__libc_start_main" ascii
        $s8 = "__init_array_start" ascii
        $s9 = "/tmp/log_de.log" ascii
        $s10 = "__init_array_end" ascii
        $s11 = ".gnu.version_r" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}

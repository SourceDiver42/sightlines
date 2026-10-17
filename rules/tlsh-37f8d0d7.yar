rule Sightlines_tlsh_37f8d0d7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-37f8d0d7"
        date = "2026-10-15"
        campaign = "tlsh-37f8d0d7"
        family = ""
        hash = "01620b119ca692d389def0230809e53331503e406251a6f97782696f3cb358d6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-37f8d0d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "Error: setsockopt() - Cannot set HDRINCL!" ascii
        $s2 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "__frame_dummy_init_array_entry" ascii
        $s6 = "Could not open raw socket." ascii
        $s7 = "_ITM_registerTMCloneTable" ascii
        $s8 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s9 = "deregister_tm_clones" ascii
        $s10 = "_GLOBAL_OFFSET_TABLE_" ascii
        $s11 = ".note.gnu.build-id" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

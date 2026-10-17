rule Sightlines_tlsh_1a07e557_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a07e557"
        date = "2026-10-15"
        campaign = "tlsh-1a07e557"
        family = "ladvix"
        hash = "5f4798c658cbb67ff1dde07cde0dbce26787e25f2d190647920c5c5a76119eac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a07e557.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "Error: setsockopt() - Cannot set HDRINCL!" ascii
        $s2 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s3 = "__libc_start_main@@GLIBC_2.2.5" ascii
        $s4 = "pthread_create@@GLIBC_2.2.5" ascii
        $s5 = "__stack_chk_fail@@GLIBC_2.4" ascii
        $s6 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s7 = "_ITM_deregisterTMCloneTable" ascii
        $s8 = "__frame_dummy_init_array_entry" ascii
        $s9 = "Could not open raw socket." ascii
        $s10 = "_ITM_registerTMCloneTable" ascii
        $s11 = "setsockopt@@GLIBC_2.2.5" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

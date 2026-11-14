rule Sightlines_tlsh_52d7e317_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52d7e317"
        date = "2026-11-13"
        campaign = "tlsh-52d7e317"
        family = "ladvix"
        hash = "057b2a85d82ec6c83eb32dd7577dc7d1f6f8ccffa36e2fe53dde7bf821de92cc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52d7e317.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "_ITM_registerTMCloneTable" ascii
        $s3 = "__libc_start_main" ascii
        $s4 = "__errno_location" ascii
        $s5 = "__stack_chk_fail" ascii
        $s6 = "__cxa_finalize" ascii
        $s7 = "__gmon_start__" ascii
        $s8 = "__strcpy_chk" ascii
        $s9 = "GLIBC_2.3.4" ascii
        $s10 = "__stpcpy_chk" ascii
        $s11 = "GLIBC_2.2.5" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

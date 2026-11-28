rule Sightlines_tlsh_4884be8c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4884be8c"
        date = "2026-11-02"
        campaign = "tlsh-4884be8c"
        family = "mirai"
        hash = "506b0987334caab33abd876085b30e7853e4e18e9759c5afeeeb890286aba575"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4884be8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s5 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s6 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s7 = "Filters not supported with LD_TRACE_PRELINKING" ascii
        $s8 = "_dl_debug_update (args.nsid)->r_state == RT_CONSISTENT" ascii
        $s9 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s10 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s11 = "_dl_debug_update (args->nsid)->r_state == RT_CONSISTENT" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1601232 and 12 of them
}

rule Sightlines_tlsh_00862500_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-00862500"
        date = "2026-11-22"
        campaign = "tlsh-00862500"
        family = "mirai"
        hash = "5dd5d3033aa1b730cd6059f5cdc4d01a8b63a1bc3d362cc7fa990c46ce96e055"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-00862500.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s4 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s5 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s9 = "ELF32_R_TYPE (reloc->r_info) == R_386_RELATIVE" ascii
        $s10 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s11 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1588312 and 12 of them
}

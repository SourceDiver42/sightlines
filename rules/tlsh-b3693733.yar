rule Sightlines_tlsh_b3693733_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b3693733"
        date = "2026-11-15"
        campaign = "tlsh-b3693733"
        family = "mirai"
        hash = "129eef01af20e6db12678ee417f17b21a5e37b15de1f249c12bebbf01daa463f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b3693733.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1309000 and 12 of them
}

rule Sightlines_tlsh_1d67764a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d67764a"
        date = "2026-10-17"
        campaign = "tlsh-1d67764a"
        family = "mirai"
        hash = "01c97268134bd3bcb04f32567f2c8b5fa2aafab4f268e7ce70ae3731566133bf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d67764a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s5 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s6 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s7 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s8 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s11 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2536224 and 12 of them
}

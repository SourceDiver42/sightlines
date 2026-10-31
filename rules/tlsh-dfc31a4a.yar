rule Sightlines_tlsh_dfc31a4a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dfc31a4a"
        date = "2026-10-29"
        campaign = "tlsh-dfc31a4a"
        family = "mirai"
        hash = "15ed3dbc8d91259c9afd897e7d21009123e7d715025198c26488c8e22db76c5c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dfc31a4a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s6 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s7 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s8 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2818992 and 10 of them
}

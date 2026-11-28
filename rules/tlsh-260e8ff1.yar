rule Sightlines_tlsh_260e8ff1_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-260e8ff1"
        date = "2026-11-21"
        campaign = "tlsh-260e8ff1"
        family = "mirai"
        hash = "40c8367759b7ec62533ce13b6d126e231d22ab23ead67ff653c81bd4e772caba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-260e8ff1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s9 = "Filters not supported with LD_TRACE_PRELINKING" ascii
        $s10 = "_dl_debug_update (args.nsid)->r_state == RT_CONSISTENT" ascii
        $s11 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1160904 and 12 of them
}

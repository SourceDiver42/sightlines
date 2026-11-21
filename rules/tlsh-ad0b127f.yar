rule Sightlines_tlsh_ad0b127f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ad0b127f"
        date = "2026-11-02"
        campaign = "tlsh-ad0b127f"
        family = "mirai"
        hash = "256bff40e010a5aa18a9bc424a76a6672ac37d48a7e9f4e72d5dfb1f71c3a67a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ad0b127f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s6 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s7 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s8 = "Filters not supported with LD_TRACE_PRELINKING" ascii
        $s9 = "_dl_debug_update (args.nsid)->r_state == RT_CONSISTENT" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2582944 and 12 of them
}

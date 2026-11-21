rule Sightlines_tlsh_8e75bd6b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8e75bd6b"
        date = "2026-11-04"
        campaign = "tlsh-8e75bd6b"
        family = "mirai"
        hash = "136a6f0521d66bf55c8b1bc7372559db4077665a05e372a1de918a1cb29f2cf0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8e75bd6b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s8 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s9 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2253012 and 12 of them
}

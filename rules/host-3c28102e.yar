rule Sightlines_host_3c28102e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-3c28102e"
        date = "2026-10-17"
        campaign = "host-3c28102e"
        family = "mirai"
        hash = "685d91b7880c6877fc0b5ab0430c503373b4280eca139cb5db2b1d50c176bc85"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-3c28102e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s5 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s9 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s10 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s11 = "lead_zero <= (base == 16 ? ((uintmax_t) exponent - (uintmax_t) INTMAX_MIN) / 4 : ((uintmax_t) expone" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2536224 and 12 of them
}

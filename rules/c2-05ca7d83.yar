rule Sightlines_c2_05ca7d83_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-05ca7d83"
        date = "2026-11-04"
        campaign = "c2-05ca7d83"
        family = "mirai"
        hash = "01b69743e92f13065a2f2b3a5c3b93e6c90c5acec797d23bb224bee9194e27aa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-05ca7d83.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s3 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s4 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "400 usage: ATTACK <method> <target> <port> <secs> [spoof=0|1 sp=min-max tos=N threads=N l4=tcp|udp|i" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2769968 and 11 of them
}

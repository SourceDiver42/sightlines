rule Sightlines_tlsh_f43f7a27_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f43f7a27"
        date = "2026-10-17"
        campaign = "tlsh-f43f7a27"
        family = "mirai"
        hash = "3073ae4acf3b53b19827c40da8f3d79c5d884adca5c9858aadb1ea4ce187f3a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f43f7a27.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "_dl_debug_initialize (0, args.nsid)->r_state == RT_CONSISTENT" ascii
        $s5 = "_dl_debug_initialize (0, args->nsid)->r_state == RT_CONSISTENT" ascii
        $s6 = "INTERNAL_SYSCALL_ERRNO (e, __err) != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHR" ascii
        $s7 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s8 = "lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)" ascii
        $s9 = "Filters not supported with LD_TRACE_PRELINKING" ascii
        $s10 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s11 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1394192 and 12 of them
}

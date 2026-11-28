rule Sightlines_tlsh_f503f825_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f503f825"
        date = "2026-11-16"
        campaign = "tlsh-f503f825"
        family = "mirai"
        hash = "9d7bb99fcdfae5e7f2a1bb223a344e6c653f72bda831150df55759cf640e6a09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f503f825.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" ascii
        $s1 = "%s: '%s' is not an ELF executable for ARCompact" ascii
        $s2 = "%s():%i: Circular dependency, skipping '%s'," ascii
        $s3 = "systemctl enable %s.service >/dev/null 2>&1 || true" ascii
        $s4 = "%s():%i: Beginning dlopen relocation fixups" ascii
        $s5 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." ascii
        $s6 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" ascii
        $s7 = "%s():%i: running dtors for library %s at '%p'" ascii
        $s8 = "%s():%i: running ctors for library %s at '%p'" ascii
        $s9 = "cannot create TLS data structures: ABORT" ascii
        $s10 = "%s: cannot apply additional memory protection after relocation" ascii
        $s11 = "cannot allocate memory in static TLS block" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

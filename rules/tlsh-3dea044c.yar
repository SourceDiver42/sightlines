rule Sightlines_tlsh_3dea044c_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3dea044c"
        date = "2026-11-11"
        campaign = "tlsh-3dea044c"
        family = "rustystealer"
        hash = "2b02bf4c5b127e2838522dd60481e99eafd667c383807604648618d9a21d6818"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3dea044c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "+ (FormatMessageW() returned invalid UTF-16)" ascii
        $s1 = "cmd.exe /e:ON /v:OFF /d /c \"batch file arguments are invalid" ascii
        $s2 = "assertion failed: len >= size_of::<c::sockaddr_in6>()" ascii
        $s3 = "fatal runtime error: I/O error: operation failed to complete synchronously, aborting" ascii
        $s4 = "fatal runtime error: the System allocator may not use TLS with destructors, aborting" ascii
        $s5 = "NotFoundPermissionDeniedConnectionRefusedConnectionResetHostUnreachableNetworkUnreachableConnectionA" ascii
        $s6 = "called `Option::unwrap()` on a `None` value" ascii
        $s7 = "9internal error: entered unreachable code: str::from_utf8(" ascii
        $s8 = "Hcannot access a Thread Local Storage value during or after destruction: " ascii
        $s9 = "&copy_from_slice: source slice length (" ascii
        $s10 = "fatal runtime error: thread local panicked on drop, aborting" ascii
        $s11 = "fatal runtime error: current thread handle already set during thread spawn, aborting" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2259968 and 12 of them
}

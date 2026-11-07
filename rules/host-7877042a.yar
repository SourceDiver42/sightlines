rule Sightlines_host_7877042a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-7877042a"
        date = "2026-10-31"
        campaign = "host-7877042a"
        family = "mirai"
        hash = "192604729aada8ede20a961fb125e2acb62f692413177754baf7068a3e654412"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-7877042a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Unrecognized address family or invalid length" ascii
        $s1 = "OpenSSL 'dlfcn' shared library method" ascii
        $s2 = "Dynamic linker failed to allocate memory for error message" ascii
        $s3 = "Dynamic loading not supported" ascii
        $s4 = "assertion failed: minsize > 0" ascii
        $s5 = "Invalid library handle %p" ascii
        $s6 = "Unrecognized socket type" ascii
        $s7 = ": unrecognized option: " ascii
        $s8 = "dlfcn_pathbyaddr(): " ascii
        $s9 = "Symbol not found: %s" ascii
        $s10 = "Name does not resolve" ascii
        $s11 = "Unrecognized service" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 16464368 and 3 of them
}

rule Sightlines_tlsh_d77b466b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d77b466b"
        date = "2026-11-15"
        campaign = "tlsh-d77b466b"
        family = "mirai"
        hash = "0d3bd681de5dc4a662bbee7ee42081a55b01c382afc54cca239d39452040278a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d77b466b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "azbd27sc1ycbgmz1dn2sf02c5tcow2lh" ascii
        $s1 = "posix_spawn_file_actions_destroy" ascii
        $s2 = "posix_spawn_file_actions_adddup2" ascii
        $s3 = "posix_spawn_file_actions_addclose" ascii
        $s4 = "posix_spawn_file_actions_init" ascii
        $s5 = "x25519_scalarmult_base" ascii
        $s6 = "GET /botstart HTTP/1.0" ascii
        $s7 = "__vdso_clock_gettime64" ascii
        $s8 = "x25519_gen_keypair" ascii
        $s9 = "__nanosleep_time64" ascii
        $s10 = "__libc_start_main" ascii
        $s11 = "pthread_sigmask" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

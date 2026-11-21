rule Sightlines_tlsh_6521b2e8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6521b2e8"
        date = "2026-11-15"
        campaign = "tlsh-6521b2e8"
        family = "mirai"
        hash = "0cb5eb1cf6134c51397a6ab56ad7a8aa9334231243dea9e2090592be2f054d23"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6521b2e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "azbd27sc1ycbgmz1dn2sf02c5tcow2lh" ascii
        $s1 = "posix_spawn_file_actions_destroy" ascii
        $s2 = "posix_spawn_file_actions_adddup2" ascii
        $s3 = "posix_spawn_file_actions_addclose" ascii
        $s4 = "posix_spawn_file_actions_init" ascii
        $s5 = "x25519_scalarmult_base" ascii
        $s6 = "GET /botstart HTTP/1.0" ascii
        $s7 = "x25519_gen_keypair" ascii
        $s8 = "__libc_start_main" ascii
        $s9 = "pthread_sigmask" ascii
        $s10 = "_DYNAMIC_LINKING" ascii
        $s11 = "__progname_full" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

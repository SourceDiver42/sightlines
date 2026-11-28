rule Sightlines_tlsh_a727ff8e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a727ff8e"
        date = "2026-11-15"
        campaign = "tlsh-a727ff8e"
        family = "mirai"
        hash = "01618a28b01efd090c269b4a9f297e59ca86c5bf8af15503e1a42877bf8931c9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a727ff8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "azbd27sc1ycbgmz1dn2sf02c5tcow2lh" ascii
        $s1 = "posix_spawn_file_actions_destroy" ascii
        $s2 = "posix_spawn_file_actions_adddup2" ascii
        $s3 = "posix_spawn_file_actions_addclose" ascii
        $s4 = "posix_spawn_file_actions_init" ascii
        $s5 = "GCC: (GNU) 11.2.1 20211120" ascii
        $s6 = "x25519_scalarmult_base" ascii
        $s7 = "GET /botstart HTTP/1.0" ascii
        $s8 = "x25519_gen_keypair" ascii
        $s9 = "__libc_start_main" ascii
        $s10 = "pthread_sigmask" ascii
        $s11 = "_DYNAMIC_LINKING" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

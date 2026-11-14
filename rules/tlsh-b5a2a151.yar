rule Sightlines_tlsh_b5a2a151_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b5a2a151"
        date = "2026-11-08"
        campaign = "tlsh-b5a2a151"
        family = "mirai"
        hash = "09f96e1b647d531dfbf749b4951e927985dfa29918a577b4e1d3bda1983ca402"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b5a2a151.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s1 = "__pthread_rwlock_timedwrlock_time64" ascii
        $s2 = "__pthread_rwlock_timedrdlock_time64" ascii
        $s3 = "pthread_rwlock_timedwrlock.c" ascii
        $s4 = "pthread_rwlock_timedrdlock.c" ascii
        $s5 = "program_invocation_short_name" ascii
        $s6 = "__pthread_timedjoin_np_time64" ascii
        $s7 = "isa_bit_quirk_no_volatile_ce" ascii
        $s8 = "__frame_dummy_init_array_entry" ascii
        $s9 = "Required key not available" ascii
        $s10 = "isa_bit_quirk_aes_1742098" ascii
        $s11 = "pthread_rwlock_tryrdlock.c" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}

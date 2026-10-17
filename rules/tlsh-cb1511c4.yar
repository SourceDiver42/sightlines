rule Sightlines_tlsh_cb1511c4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cb1511c4"
        date = "2026-10-16"
        campaign = "tlsh-cb1511c4"
        family = "mirai"
        hash = "564b6ed7237dc4aee58af9054621ced2c5ae4fc1d2673d9735c6457b6be9d6c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cb1511c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
        $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" ascii
        $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" ascii
        $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" ascii
        $s7 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" ascii
        $s8 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s9 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" ascii
        $s10 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s11 = "phase2_call_unexpected_after_unwind" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

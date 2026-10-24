rule Sightlines_tlsh_cb1511c4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cb1511c4"
        date = "2026-10-24"
        campaign = "tlsh-cb1511c4"
        family = "mirai"
        hash = "152dc9cbc719596a18b8f7f4ce8ab89cb6c9c3f747cc7f06a2121480d5c91d8d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cb1511c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
        $s2 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" ascii
        $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" ascii
        $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" ascii
        $s5 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" ascii
        $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" ascii
        $s7 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s8 = "phase2_call_unexpected_after_unwind" ascii
        $s9 = "_Unwind_GetLanguageSpecificData" ascii
        $s10 = "_Unwind_VRS_DataRepresentation" ascii
        $s11 = "__gnu_Unwind_Resume_or_Rethrow" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}

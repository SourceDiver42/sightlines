rule Sightlines_imphash_52c46df4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-52c46df4"
        date = "2026-11-22"
        campaign = "imphash-52c46df4"
        family = ""
        hash = "02c1257c49f3efc7841d19b97b30298ab96fa614f977aebbe955a175c7bb617c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-52c46df4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (x86_64-win32-seh-rev1, Built by MinGW-Builds project) 13.2.0" ascii
        $s1 = "C:/buildroot/x86_64-1320-win32-seh-ucrt-rt_v11-rev1/build/gcc-13.2.0/x86_64-w64-mingw32/libgcc" ascii
        $s2 = "C:\\buildroot\\x86_64-1320-win32-seh-ucrt-rt_v11-rev1\\build\\gcc-13.2.0\\x86_64-w64-mingw32\\libgcc" ascii
        $s3 = "GNU C17 13.2.0 -mtune=core2 -march=nocona -g -g -g -O2 -O2 -O2 -fno-ident -fPIC -fbuilding-libgcc -f" ascii
        $s4 = "C:/buildroot/src/gcc-13.2.0/libgcc/config/i386\\cygwin.S" ascii
        $s5 = "C:/buildroot/src/gcc-13.2.0/gcc/config/i386" ascii
        $s6 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s7 = "X86_TUNE_SSE_PARTIAL_REG_FP_CONVERTS_DEPENDENCY" ascii
        $s8 = "_head_lib64_libapi_ms_win_crt_environment_l1_1_0_a" ascii
        $s9 = "C:/buildroot/src/gcc-13.2.0/libgcc/libgcc2.c" ascii
        $s10 = "X86_TUNE_SSE_PARTIAL_REG_CONVERTS_DEPENDENCY" ascii
        $s11 = "_head_lib64_libapi_ms_win_crt_runtime_l1_1_0_a" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

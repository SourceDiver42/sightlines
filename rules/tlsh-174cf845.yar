rule Sightlines_tlsh_174cf845_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-174cf845"
        date = "2026-11-15"
        campaign = "tlsh-174cf845"
        family = "mirai"
        hash = "546bc17e05773d7dc061abd01ad00da45b0de68d0b10247003186488b023316b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-174cf845.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s4 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
        $s5 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/pr-support.c" ascii
        $s6 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/libunwind.S" ascii
        $s7 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/unwind-c.c" ascii
        $s8 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/unwind-arm.c" ascii
        $s9 = "/home/landley/aboriginal/aboriginal/build/simple-cross-compiler-armv7l/bin/../cc/include" ascii
        $s10 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/build-gcc/gcc" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

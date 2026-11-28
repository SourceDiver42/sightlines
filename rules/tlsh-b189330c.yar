rule Sightlines_tlsh_b189330c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b189330c"
        date = "2026-11-21"
        campaign = "tlsh-b189330c"
        family = ""
        hash = "7eafad96046a1741395c6fbf4428f3bedc604f7ae044a4615c0720de7ab4d551"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b189330c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Floating-point stack overflow or underflow" wide
        $s1 = "Floating-point underflow (exponent too small)" wide
        $s2 = "Floating-point overflow (exponent to great)" wide
        $s3 = "Exception handler returned unknown value" wide
        $s4 = "Exception handler tried to continue after non-continuable exception" wide
        $s5 = "Division by zero (floating-point)" wide
        $s6 = "Invalid floating-point operation" wide
        $s7 = "Denormal floating-point operand" wide
        $s8 = "Inexact floating-point result" wide
        $s9 = "Debugger breakpoint reached" wide
        $s10 = "Invalid memory access" wide
        $s11 = "PathRemoveBackslashW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

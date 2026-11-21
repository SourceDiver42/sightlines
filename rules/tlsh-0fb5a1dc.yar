rule Sightlines_tlsh_0fb5a1dc_babadeda
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0fb5a1dc"
        date = "2026-11-16"
        campaign = "tlsh-0fb5a1dc"
        family = "babadeda"
        hash = "063a1e469ce2874bb41cf3549d73eada29d94612fad036d10f8088f2be45e8ec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0fb5a1dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " inflate 1.2.11 Copyright 1995-2017 Mark Adler " ascii
        $s1 = "    name=\"CompanyName.ProductName.YourApp\"" ascii
        $s2 = "Floating-point stack overflow or underflow" wide
        $s3 = "Floating-point underflow (exponent too small)" wide
        $s4 = "Floating-point overflow (exponent to great)" wide
        $s5 = "Exception handler returned unknown value" wide
        $s6 = "Exception handler tried to continue after non-continuable exception" wide
        $s7 = "Division by zero (floating-point)" wide
        $s8 = "</assembly>PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGX" ascii
        $s9 = "        processorArchitecture=\"X86\"" ascii
        $s10 = "Invalid floating-point operation" wide
        $s11 = "Denormal floating-point operand" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

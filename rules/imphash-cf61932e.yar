rule Sightlines_imphash_cf61932e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cf61932e"
        date = "2026-11-07"
        campaign = "imphash-cf61932e"
        family = ""
        hash = "671d7959b4e5ee8306f7e96fb605f14bf5d206ed5177b79d006d29f44218ce64"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cf61932e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s2 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s3 = "\"C:\\Windows\\System32\\nvidia-smi.exe\"" wide
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "Chrome GPU Monitor (x86)" wide
        $s10 = "8MZuCHcP<H" ascii
        $s11 = "__initenv" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

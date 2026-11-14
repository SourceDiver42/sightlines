rule Sightlines_imphash_6262213f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-6262213f"
        date = "2026-11-02"
        campaign = "imphash-6262213f"
        family = ""
        hash = "10019206c59be2f1409a6c1e4d2f7249cc2ac564100c352cfc114dcfc57b0b89"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-6262213f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "Total loss of significance (TLOSS)" ascii
        $s4 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s5 = "Overflow range error (OVERFLOW)" ascii
        $s6 = "Argument domain error (DOMAIN)" ascii
        $s7 = "Argument singularity (SIGN)" ascii
        $s8 = "runtime error %d" ascii
        $s9 = "8MZuMHcP<" ascii
        $s10 = "9MZu<HcQ<" ascii
        $s11 = "@.buildid" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1502744 and 12 of them
}

rule Sightlines_tlsh_4975044f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4975044f"
        date = "2026-10-22"
        campaign = "tlsh-4975044f"
        family = ""
        hash = "2fd42f6f803f274b6fd8c96a25fca7850f6b2907b9201b116eda6c4e6614a606"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4975044f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-msvcrt-posix-seh, built by Brecht Sanders) 13.1.0" ascii
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "C:\\Users\\%s\\AppData\\Roaming" wide
        $s10 = "%s\\Google\\Chrome\\Update" wide
        $s11 = "Google Installer (x86)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 10340832 and 12 of them
}

rule Sightlines_imphash_0f332b3d_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0f332b3d"
        date = "2026-11-24"
        campaign = "imphash-0f332b3d"
        family = "netsupport"
        hash = "24294bb46842f08d3f37989de1f47d0aef9eaffa1fc9eea3ceda173702978641"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0f332b3d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "api-ms-win-crt-multibyte-l1-1-0.dll" ascii
        $s4 = "Total loss of significance (TLOSS)" ascii
        $s5 = "C:\\Windows\\System32\\shell32.dll" ascii
        $s6 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s7 = "Overflow range error (OVERFLOW)" ascii
        $s8 = "Argument domain error (DOMAIN)" ascii
        $s9 = "Argument singularity (SIGN)" ascii
        $s10 = "Windows Update Service" ascii
        $s11 = "%s\\WindowsUpdate.lnk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12455844 and 12 of them
}

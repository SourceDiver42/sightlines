rule Sightlines_contacted_05943701_psychedelicstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-05943701"
        date = "2026-11-03"
        campaign = "contacted-05943701"
        family = "psychedelicstealer"
        hash = "101c3ba820044cd24971c946c10109b65fd76bca3db3065f13a65e93a836b98e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-05943701.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "Total loss of significance (TLOSS)" ascii
        $s4 = "Overflow range error (OVERFLOW)" ascii
        $s5 = "Argument domain error (DOMAIN)" ascii
        $s6 = "Argument singularity (SIGN)" ascii
        $s7 = "WinHttpReceiveResponse" ascii
        $s8 = "WinHttpSendRequest" ascii
        $s9 = "WinHttpOpenRequest" ascii
        $s10 = "WinHttpReadData" ascii
        $s11 = "WinHttpConnect" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8884398 and 12 of them
}

rule Sightlines_tlsh_30940f2d_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-30940f2d"
        date = "2026-10-24"
        campaign = "tlsh-30940f2d"
        family = "salatstealer"
        hash = "02fa9c7b88f443b451e7f03bdb723558cc8db7c35eee130e3fd17429813b00c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-30940f2d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GBZAP-PACK-UNIQUE" ascii
        $s1 = "KbpxF9v|1<`J~|" ascii
        $s2 = "{}z4:RHGd,X,NB" ascii
        $s3 = "'i]m&yNefvj}" ascii
        $s4 = "BzawNgE[Q|K`" ascii
        $s5 = "Gz4!d|#D<Ogb" ascii
        $s6 = "im|5?2K0l}\\4" ascii
        $s7 = "F:[`qIQAC>tQ" ascii
        $s8 = "Cneq^6!+KezX" ascii
        $s9 = "!amb)&zg-s3" ascii
        $s10 = "=:0<,8OADcK" ascii
        $s11 = "MI{O*qR%!h5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7186080 and 12 of them
}

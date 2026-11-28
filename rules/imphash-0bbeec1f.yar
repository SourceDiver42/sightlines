rule Sightlines_imphash_0bbeec1f_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0bbeec1f"
        date = "2026-11-10"
        campaign = "imphash-0bbeec1f"
        family = "remcos"
        hash = "065cfe7c9627cdef0dadc03338668855153c6ca2d758194d455cf9f0a20ce432"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0bbeec1f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@6DE91A942B043ED565\\" ascii
        $s1 = "CredentialUIBroker" wide
        $s2 = "@rtbAtYatTStpKstFu" ascii
        $s3 = " 1$(VOKa3R#nTE" ascii
        $s4 = "8~ QSItNP6WH\"G" ascii
        $s5 = "fQ98(~7c%/VHee" ascii
        $s6 = " eL#/Rc*q6(Lf" ascii
        $s7 = ",TEdNct$T[v[S" ascii
        $s8 = "{*`DFCQ455Ds#" ascii
        $s9 = "WedThuFriSat" ascii
        $s10 = "APPLOCKERCSP4" wide
        $s11 = ">`[9~hJhHZFY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3213936 and 12 of them
}

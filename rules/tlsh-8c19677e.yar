rule Sightlines_tlsh_8c19677e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8c19677e"
        date = "2026-11-09"
        campaign = "tlsh-8c19677e"
        family = ""
        hash = "433d0623db27177ea6451317b6fa4079526ebfd9ede5860120885a9a2230898e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8c19677e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".l=Hs{bS7jn`Z" ascii
        $s1 = "h:wx%?zOr!BgY" ascii
        $s2 = "]8SmFz0]Y*+VI" ascii
        $s3 = "x6)4Wyvc&ti`" ascii
        $s4 = "iCeL(J8_{L*j" ascii
        $s5 = "mmHrXh[yo3w~" ascii
        $s6 = "bte{<<2eV>Fm" ascii
        $s7 = "Ud*S]icd]jpC" ascii
        $s8 = "%kS6X70rJwV" ascii
        $s9 = ";V?eE!vrb)Z" ascii
        $s10 = ";`8ZhNHq{Sb" ascii
        $s11 = "=IvNfTX^\\nF" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7185408 and 12 of them
}

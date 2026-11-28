rule Sightlines_imphash_e7ce2491_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e7ce2491"
        date = "2026-11-03"
        campaign = "imphash-e7ce2491"
        family = "revstealer"
        hash = "5ba5a33fa477b0bd1146714e96ab618b1c99d8b1ea8ab78c6f3fde5b791530f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e7ce2491.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ExtractIconW" ascii
        $s1 = ",P 62uU`W" ascii
        $s2 = "`mH/Mcs%" ascii
        $s3 = " 588I]'d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9793536 and 4 of them
}

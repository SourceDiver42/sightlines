rule Sightlines_tlsh_f0f54d8b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f0f54d8b"
        date = "2026-11-01"
        campaign = "tlsh-f0f54d8b"
        family = ""
        hash = "290927f274371e4dfe49216c5f9c8b5a6e346ad4dd7462101349ee7933930c70"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f0f54d8b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "l$49F8te" ascii
        $s1 = "xJtuRRPV" ascii
        $s2 = "3T$83D$4" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}

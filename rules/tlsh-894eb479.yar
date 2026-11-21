rule Sightlines_tlsh_894eb479_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-894eb479"
        date = "2026-11-01"
        campaign = "tlsh-894eb479"
        family = ""
        hash = "2940592f5fa845df91401349e4b32bdb8c277fab19347709da98123daa5f5ed4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-894eb479.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "l$49F8te" ascii
        $s1 = "|$(WVQRP" ascii
        $s2 = "xJtuRRPV" ascii
        $s3 = "3L$t3\\$x" ascii
        $s4 = "3T$83D$4" ascii
        $s5 = "tk;L$0tk" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1214464 and 6 of them
}

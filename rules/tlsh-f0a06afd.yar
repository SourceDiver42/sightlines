rule Sightlines_tlsh_f0a06afd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f0a06afd"
        date = "2026-10-31"
        campaign = "tlsh-f0a06afd"
        family = ""
        hash = "33ad779bbab565194bd128990c3a104d92c00d1eefb3b15c924714a933aeef5f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f0a06afd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "l$49F8te" ascii
        $s1 = "|$(WVQRP" ascii
        $s2 = "xJtuRRPV" ascii
        $s3 = "3L$t3\\$x" ascii
        $s4 = "3T$83D$4" ascii
        $s5 = "tk;L$0tk" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1181696 and 6 of them
}

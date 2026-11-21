rule Sightlines_imphash_281cc298_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-281cc298"
        date = "2026-11-15"
        campaign = "imphash-281cc298"
        family = "revstealer"
        hash = "3925c9ae4d10b2379236b787b8edd07a3128da929b1244b9587f738f961386be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-281cc298.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xAFt>Z`V;" ascii
        $s1 = "ylsj[hhs)" ascii
        $s2 = "75xq)2,s" ascii
        $s3 = "8db{WTJt" ascii
        $s4 = "9K6Y0r%t" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10093568 and 5 of them
}

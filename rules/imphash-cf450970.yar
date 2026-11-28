rule Sightlines_imphash_cf450970_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cf450970"
        date = "2026-11-21"
        campaign = "imphash-cf450970"
        family = ""
        hash = "793bb7e600e37f23a7b6c65a6f7248a851438fa510871726e83f8d1966b7b95d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cf450970.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "QueryFullProcessImageNameA" ascii
        $s1 = "Local\\WDPROD" ascii
        $s2 = "ncrthost.dll" ascii
        $s3 = "Local\\WDS" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

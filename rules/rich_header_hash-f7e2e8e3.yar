rule Sightlines_rich_header_hash_f7e2e8e3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-f7e2e8e3"
        date = "2026-11-13"
        campaign = "rich_header_hash-f7e2e8e3"
        family = ""
        hash = "996645d7f16a6294babb6da83478062aed7b72318d7a51b66e90ab5d3edc51a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-f7e2e8e3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "callback%d" wide
        $s1 = "010D0M0`0i0" ascii
        $s2 = "StrAlloc" ascii
        $s3 = "<t~HtmHt;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}

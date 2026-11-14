rule Sightlines_rich_header_hash_9cc7bdc8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-9cc7bdc8"
        date = "2026-11-07"
        campaign = "rich_header_hash-9cc7bdc8"
        family = ""
        hash = "145ebbda410554e9e1f203ef9c600c1beb342f1fb00b784578291e252ccc09aa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-9cc7bdc8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nolmjkhifgdebc`a~" ascii
        $s1 = "NtQueryObject" ascii
        $s2 = "WINSPOOL.DRV" ascii
        $s3 = "RegEnumKeyW" ascii
        $s4 = "MSIMG32.dll" ascii
        $s5 = "joyGetPos" ascii
        $s6 = "nf~vNF^V" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 28721024 and 7 of them
}

rule Sightlines_rich_header_hash_ea9397fd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-ea9397fd"
        date = "2026-11-09"
        campaign = "rich_header_hash-ea9397fd"
        family = ""
        hash = "1caab35b16e0a766004c2bc4194de67491938c4f92b6d3f4e5a5ce60682fd6ca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-ea9397fd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Host Process for Windows Service" wide
        $s1 = "Copyright (C) 2016" wide
        $s2 = "sqhost.exe" wide
        $s3 = "j[B,K^C1f" ascii
        $s4 = "wsprintfA" ascii
        $s5 = "C{[M8K_I" ascii
        $s6 = "zG)S{9ut" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1181776 and 7 of them
}

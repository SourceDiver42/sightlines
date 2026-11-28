rule Sightlines_rich_header_hash_9f16ab86_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-9f16ab86"
        date = "2026-11-24"
        campaign = "rich_header_hash-9f16ab86"
        family = "wannacry"
        hash = "4429d616c8274f057a1fa35be502ba734a873943fe31d33fd1644e8db124aae5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-9f16ab86.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lMzD/5HeW^M}#}" ascii
        $s1 = "bX#aAZ0/O3R`+" ascii
        $s2 = "YWj\\_f9>uOf9~" ascii
        $s3 = "C57Q<=rN'*RV" ascii
        $s4 = "`Uv1J0oZ[MqI" ascii
        $s5 = "lD.yn)U_7<9C" ascii
        $s6 = "BqZ=(JjQ:cS" ascii
        $s7 = "]p,-WTj6Bg(" ascii
        $s8 = "fg|tLRKVj`Q" ascii
        $s9 = "{82O~\"ZLTl^" ascii
        $s10 = ")FD~p5PgPl{" ascii
        $s11 = "Q8-8|NKLcP%" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4123876 and 9 of them
}

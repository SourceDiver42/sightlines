rule Sightlines_rich_header_hash_9f16ab86_wannacry
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-9f16ab86"
        date = "2026-11-07"
        campaign = "rich_header_hash-9f16ab86"
        family = "wannacry"
        hash = "4429d616c8274f057a1fa35be502ba734a873943fe31d33fd1644e8db124aae5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-9f16ab86.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lMzD/5HeW^M}#}" ascii
        $s1 = "YWj\\_f9>uOf9~" ascii
        $s2 = "`Uv1J0oZ[MqI" ascii
        $s3 = "lD.yn)U_7<9C" ascii
        $s4 = "BqZ=(JjQ:cS" ascii
        $s5 = "fg|tLRKVj`Q" ascii
        $s6 = "_-TPsPUv: V" ascii
        $s7 = ")FD~p5PgPl{" ascii
        $s8 = "Q8-8|NKLcP%" ascii
        $s9 = "wz1JV+U^uV " ascii
        $s10 = " +nW]$JpA7" ascii
        $s11 = ">LYFJu^$RO" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4123876 and 12 of them
}

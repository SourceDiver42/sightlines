rule Sightlines_tlsh_ef342dc8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef342dc8"
        date = "2026-11-23"
        campaign = "tlsh-ef342dc8"
        family = "mirai"
        hash = "102073d685cb6b1c9b5e28ee652bee362909d1d7cb711f4c9930f11e22714c2b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef342dc8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "traceAddr=%%3A%%3A1&trys=3&timeout=30&datasize=%s&maxhop=1&wanif=65535&go=+Go&submit-url=%%2Ftracert" ascii
        $s1 = "pingAddr=%s&wanif=65535&go=+Ping&submit-url=%%2Fping6.asp" ascii
        $s2 = "[cmd] RECEIVED cid=%u duration=%u vector=%u targets_hdr=%u plen=%u" ascii
        $s3 = "[cb1] encrypted C2 lookup failed, falling back to %s" ascii
        $s4 = "[flood] REJECT vector=%u duration=%u targets=%u" ascii
        $s5 = "[flood] vec_udp: raw sendto failed errno=%d dst=%08x" ascii
        $s6 = "[flood] COMMAND cid=%u flood=%s duration=%us vector=%u targets=%u opts=%u" ascii
        $s7 = "[cmd] PARSED vector=%u targets=%u opts=%u" ascii
        $s8 = "[flood] vec_udp: first dst=%08x sa=%08x dport=%d" ascii
        $s9 = "[flood] START vector=%u duration=%u targets=%u threads=%d" ascii
        $s10 = "[flood] vec_udp: udp sendto failed errno=%d dst=%08x" ascii
        $s11 = "GET /boaform/adminformLogout//boaform/admin/login.asp HTTP/1.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

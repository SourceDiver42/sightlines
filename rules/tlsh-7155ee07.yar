rule Sightlines_tlsh_7155ee07_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7155ee07"
        date = "2026-11-14"
        campaign = "tlsh-7155ee07"
        family = "mirai"
        hash = "15f97ac71c17d65347c01e5c3e0bc5590e67812e313749c65858f70e2d6b7e5f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7155ee07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s1 = "DlSigEd25519 no Ed25519 collisions" ascii
        $s2 = "Accept: application/dns-message" ascii
        $s3 = "#(,048<@DHLPTX\\`dhlptx|" wide
        $s4 = " $(,048<@DHLPTX]bgoty~" wide
        $s5 = "POST /dns-query HTTP/1.1" ascii
        $s6 = "6aWccaT waV}b7U,a#m4tw" ascii
        $s7 = "/etc/config/resolv.conf" ascii
        $s8 = "cn3,73a~41+Cg)A(G{!" ascii
        $s9 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s10 = "cloudflare-dns.com" ascii
        $s11 = "e1:q9:get_peers1:t2:" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

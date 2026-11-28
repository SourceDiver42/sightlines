rule Sightlines_tlsh_a30d1529_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a30d1529"
        date = "2026-11-14"
        campaign = "tlsh-a30d1529"
        family = "mirai"
        hash = "a7763a0a0cc4c90039e16b8151ea5edf2f8b86d45fdaed75af0d2d3872dad830"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a30d1529.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s1 = "Accept: application/dns-message" ascii
        $s2 = "#(,048<@DHLPTX\\`dhlptx|" wide
        $s3 = " $(,048<@DHLPTX]bgoty~" wide
        $s4 = "POST /dns-query HTTP/1.1" ascii
        $s5 = "cloudflare-dns.com" ascii
        $s6 = "e1:q9:get_peers1:t2:" ascii
        $s7 = "3:seqi%llde3:sig64:" ascii
        $s8 = "PlmzmzmeC$B$eA$@$Q" ascii
        $s9 = "3:seqi%llde1:v%d:" ascii
        $s10 = "9:info_hash20:" ascii
        $s11 = "e1:q4:ping1:t2:" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_90182bb0_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90182bb0"
        date = "2026-10-23"
        campaign = "tlsh-90182bb0"
        family = "gafgyt"
        hash = "646026303b48c55cc1cb48b406bddff35e952b615720217bacf6728a1d448822"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90182bb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "upgrade-insecure-requests" ascii
        $s4 = "__vdso_clock_gettime64" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = ".note.gnu.property" ascii
        $s9 = "/proc/self/status" ascii
        $s10 = "sec-ch-ua-mobile" ascii
        $s11 = "GET %s HTTP/1.1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

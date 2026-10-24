rule Sightlines_tlsh_07ae73b1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-07ae73b1"
        date = "2026-10-24"
        campaign = "tlsh-07ae73b1"
        family = ""
        hash = "477b83feba08216cd52e6d16b15732e49ca5557e2648c1427dd12e9f4eba60cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-07ae73b1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "ULT-STY-te k2-bynd 3expa0001" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "Connection: keep-alive" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = "/proc/self/status" ascii
        $s9 = "sec-ch-ua-mobile" ascii
        $s10 = "GET %s HTTP/1.1" ascii
        $s11 = "en-US,en;q=0.9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

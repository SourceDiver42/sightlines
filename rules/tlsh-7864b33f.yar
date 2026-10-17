rule Sightlines_tlsh_7864b33f_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7864b33f"
        date = "2026-10-15"
        campaign = "tlsh-7864b33f"
        family = "mirai"
        hash = "2a3aab2a262a9fccf8c35ebe2fdfe08f533395a4cf78b2cb202e5ca2129c5c4e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7864b33f.json"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

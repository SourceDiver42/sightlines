rule Sightlines_tlsh_913890e0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-913890e0"
        date = "2026-10-30"
        campaign = "tlsh-913890e0"
        family = "mirai"
        hash = "222a01338329ff0c5413b22fbfc4f96d0b9d0b60cdba7b68e6956a7b81a59470"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-913890e0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s1 = " 2>/dev/null || /bin/busybox wget -q http://%s/x86 2>/dev/null; chmod 777 mips mpsl arm7 arm8 x86 2>" ascii
        $s2 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s3 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s4 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s5 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s6 = "http://%s/arm8 2>/dev/null || /bin/busybox wget -q http://%s/arm8 2>/dev/null; wget -q http://%s/x86" ascii
        $s7 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s8 = "ull; wget -q http://%s/arm7 2>/dev/null || /bin/busybox wget -q http://%s/arm7 2>/dev/null; wget -q " ascii
        $s9 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s10 = "cat > \"$d/network-dispatch.service\" <<EOF" ascii
        $s11 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}

rule Sightlines_tlsh_e69583c9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e69583c9"
        date = "2026-10-24"
        campaign = "tlsh-e69583c9"
        family = "mirai"
        hash = "69f5e308a0de8e4f8bd5793ab2403b8598f287354febdb85520002d8ef39feba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e69583c9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s9 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s10 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s11 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

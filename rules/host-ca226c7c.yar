rule Sightlines_host_ca226c7c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-ca226c7c"
        date = "2026-10-18"
        campaign = "host-ca226c7c"
        family = "mirai"
        hash = "690e5586023270cbdf3bbef3a2206d3fb3bce08c5950c81969ab55056f0324bc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-ca226c7c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s2 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s3 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s4 = "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13" ascii
        $s5 = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" ascii
        $s6 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s7 = "SSH-2.0-PuTTY_Release_0.78" ascii
        $s8 = "X-Forwarded-For: 127.0.0.1" ascii
        $s9 = "SSH-2.0-Dropbear_2022.83" ascii
        $s10 = "HOST: 255.255.255.255:1900" ascii
        $s11 = "Connection: keep-alive" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2287376 and 12 of them
}

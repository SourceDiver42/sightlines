rule Sightlines_host_f7f511d2_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-f7f511d2"
        date = "2026-10-17"
        campaign = "host-f7f511d2"
        family = "mirai"
        hash = "060b43e899cf21bee854bd3b7cab84024328c95961570f72c22b359bc327129e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-f7f511d2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s2 = "[%s] udp_legit: %d threads preset (nproc=%d), size=%d, %ds" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = "[%s] syn_hs established %d flows (%ld ok, %ld fail), now spewing" ascii
        $s6 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s7 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s8 = "[%s] udp_legit worker done: %ld pkts x %d B" ascii
        $s9 = "[%s] udpcustom: sendto failed after %ld pkts: %s" ascii
        $s10 = "[%s] ovhbypass: mode=%s port=%d size=%d burst=%d gap=%dms %ds" ascii
        $s11 = "[%s] udp_legit done: %d threads, %d secs" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1394192 and 12 of them
}

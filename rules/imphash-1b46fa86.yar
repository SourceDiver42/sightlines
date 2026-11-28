rule Sightlines_imphash_1b46fa86_prometei
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1b46fa86"
        date = "2026-11-09"
        campaign = "imphash-1b46fa86"
        family = "prometei"
        hash = "63adf9ad9100e1925cb5d54456c8ff429c6f236c61eb50554d8ecffa4e92077a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1b46fa86.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "+GW8XDtV3huKyEyTSnlQJ3n6oqYB832WJzKRRWS3haFMxdbjZPD9CgT7QYx8BV8pv1/ftnX5QRW5TWuYAVe/VSFSHDUZgZpy+lxD" ascii
        $s1 = "TqOS3UcSZ7O/VjZIYmJTeLGq0in9mvVY1zc8HlnI6hrBZ2Ef8wVk2ZAbk15cKLg9PS7niXA=" ascii
        $s2 = "/C reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\UPlugPlay\" /v ImagePath /f /t REG_E" ascii
        $s3 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi" ascii
        $s4 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.zero/cgi-bin/prometei.cgi" ascii
        $s5 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" ascii
        $s6 = "SOFTWARE\\Microsoft\\VisualStudio\\9.0\\Setup\\VS" ascii
        $s7 = "/C reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v " ascii
        $s8 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s9 = "/C netsh advfirewall firewall add rule name=\"Secure Socket Tunneling Protocol (HTTP)\" dir=in action=" ascii
        $s10 = "/C Auditpol /set /subcategory:\"Logon\" /failure:enable" ascii
        $s11 = "http://%s/cgi-bin/p.cgi?r=0&auth=hash&i=%s&enckey=%s" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

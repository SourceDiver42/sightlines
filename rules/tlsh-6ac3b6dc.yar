rule Sightlines_tlsh_6ac3b6dc_nightshadec2
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ac3b6dc"
        date = "2026-11-17"
        campaign = "tlsh-6ac3b6dc"
        family = "nightshadec2"
        hash = "6d68d0a96c8bc726cbe3bf6f6253fb0ccae50627e966b8606f3582ef65eacec7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ac3b6dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = "<meta\\s+property=\"og:title\"\\s+content=\"Steam Community :: ([^\"]{0,255})\\\"" ascii
        $s3 = "SELECT value_encrypted FROM local_stored_cvc WHERE guid = '%ws'" wide
        $s4 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" wide
        $s5 = "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Opera Browser.lnk" wide
        $s6 = "$archpath = \"C:\\ProgramData\\Krutyak.zip\"; $unpackpath = \"C:\\ProgramData\";Expand-Archive $archpath -D" ascii
        $s7 = "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s8 = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies" wide
        $s9 = "SELECT host_key, path, is_secure, expires_utc, name, encrypted_value FROM cookies" wide
        $s10 = "%LOCALAPPDATA%\\Microsoft\\Edge\\Application\\msedge.exe" wide
        $s11 = "SELECT * FROM sqlite_master WHERE type='table'" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3496960 and 12 of them
}

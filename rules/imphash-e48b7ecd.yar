rule Sightlines_imphash_e48b7ecd_mmtwstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e48b7ecd"
        date = "2026-11-07"
        campaign = "imphash-e48b7ecd"
        family = "mmtwstealer"
        hash = "0962fa75fd750a0cb3c9cc33a86feabffbd79fcf597fcd200d01c81bef93f225"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e48b7ecd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = "SELECT origin_url, username_value, password_value FROM logins WHERE password_value != '' AND length(" ascii
        $s3 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s4 = "GCC: (Rev13, Built by MSYS2 project) 15.2.0" ascii
        $s5 = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000" ascii
        $s6 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s7 = "Login DaNetwork\\Web DataSELECT name, value FROM autofillTelegram Desktop" ascii
        $s8 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s9 = "SELECT host, name, value, path, expiry, isSecure, isHttpOnly FROM moz_cookies" ascii
        $s10 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ascii
        $s11 = "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2480128 and 12 of them
}

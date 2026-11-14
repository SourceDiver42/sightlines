rule Sightlines_tlsh_bb55f293_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bb55f293"
        date = "2026-11-13"
        campaign = "tlsh-bb55f293"
        family = ""
        hash = "49e0885d1390cde3b5775cbb28589aba956e81921910e779a1c8eb7b1b7fa74a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bb55f293.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s3 = "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" wide
        $s4 = "SELECT value FROM meta WHERE key='local_encryptor_data'" ascii
        $s5 = "SELECT item1,item2 FROM metadata WHERE id='password'" ascii
        $s6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles" wide
        $s7 = "SELECT origin_url, username_value, password_value, date_created" ascii
        $s8 = "SELECT origin_url, username_element, username_value, password_element, password_value, signon_realm," ascii
        $s9 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" wide
        $s10 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles" wide
        $s11 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1984512 and 12 of them
}

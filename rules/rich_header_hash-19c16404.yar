rule Sightlines_rich_header_hash_19c16404_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-19c16404"
        date = "2026-11-21"
        campaign = "rich_header_hash-19c16404"
        family = ""
        hash = "63589400390cdae0b5021f6d6aadc0b087baf6b2888acc3cbb966382dc6613b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-19c16404.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676\\" wide
        $s1 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command\\" wide
        $s2 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchit" ascii
        $s3 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" ascii
        $s4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s5 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\" wide
        $s6 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676\\" wide
        $s7 = "G*\\AC:\\Users\\Administrator\\AppData\\Roaming\\Microsoft\\Windows\\Templates\\Stub\\Project1.vbp" wide
        $s8 = "If Not WScript.Arguments.Named.Exists(\"elevated\") Then" wide
        $s9 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\Edge.exe" wide
        $s10 = "SELECT hostname, encryptedUsername, encryptedPassword  FROM moz_logins" wide
        $s11 = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*RD_" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1122304 and 11 of them
}

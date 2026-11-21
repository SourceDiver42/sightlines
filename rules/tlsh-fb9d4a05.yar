rule Sightlines_tlsh_fb9d4a05_a310logger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fb9d4a05"
        date = "2026-11-10"
        campaign = "tlsh-fb9d4a05"
        family = "a310logger"
        hash = "9c22b3bcc79b5d5cc8bde5f5ba4fa8d705cd3d51bd0ab2f3a4c67099b712f483"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fb9d4a05.json"
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
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

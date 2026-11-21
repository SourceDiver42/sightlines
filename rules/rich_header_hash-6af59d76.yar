rule Sightlines_rich_header_hash_6af59d76_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6af59d76"
        date = "2026-11-18"
        campaign = "rich_header_hash-6af59d76"
        family = "remcos"
        hash = "24a6ed8ce6aa9fb2c29a706882efd3f3e1dec98517fc0e50b36a09543b6c69e0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6af59d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s3 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s4 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s5 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s6 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s9 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s10 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s11 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}

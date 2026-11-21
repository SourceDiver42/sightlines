rule Sightlines_contacted_dddd34e5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-dddd34e5"
        date = "2026-11-18"
        campaign = "contacted-dddd34e5"
        family = ""
        hash = "16745f37f9a903bc0b932bfc57dc3b1ac2cefc8a207639c224f6a84c79dbb275"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-dddd34e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Google\\Chrome\\Application\\chrome.exe" wide
        $s4 = "BraveSoftware\\Brave-Browser\\User Data" wide
        $s5 = "Yandex\\YandexBrowser\\User Data" wide
        $s6 = "Opera Software\\Opera GX Stable" wide
        $s7 = "Opera Software\\Opera Stable" wide
        $s8 = "Microsoft\\Edge\\User Data" wide
        $s9 = "Google\\Chrome\\User Data" wide
        $s10 = "http://ip-api.com/json/" wide
        $s11 = "Vivaldi\\User Data" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

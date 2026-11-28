rule Sightlines_imphash_4ea5893c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4ea5893c"
        date = "2026-11-02"
        campaign = "imphash-4ea5893c"
        family = ""
        hash = "34884d3f7b1bf48ea673e053a71d4aa0d309422ab04cd91eadbb5133fa2a35b5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4ea5893c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "pqrstuvwhijklmno`abcdefgXYZ[\\]^_PQRSTUVWHIJKLMNO@ABCDEFG" ascii
        $s1 = "C:\\Program Files\\Mullvad VPN\\Configs\\Mullvad" wide
        $s2 = "C:\\Program Files\\WireGuard\\Data\\Configurations" wide
        $s3 = "C:\\ProgramData\\Oray\\SunloginClient\\config.ini" wide
        $s4 = "C:\\Program Files\\hidemy.name VPN 2.0" wide
        $s5 = "C:\\ProgramData\\AnyDesk\\service.conf" wide
        $s6 = "C:\\Program Files\\PuTTY\\putty.log" wide
        $s7 = "Local Extension Settings" wide
        $s8 = "Sync Extension Settings" wide
        $s9 = "service.json.bak" wide
        $s10 = "wvbots\\EBWebView" wide
        $s11 = "3yPjCGGGhPCcP" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17096750 and 12 of them
}

rule Sightlines_imphash_2a95e4a4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-2a95e4a4"
        date = "2026-11-15"
        campaign = "imphash-2a95e4a4"
        family = ""
        hash = "1b1732a90ccac50feada6a3d1ec87b89e7258afac8016d820296f461a432ae67"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-2a95e4a4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_com_sun_security_auth_module_NTSystem_getImpersonationToken0" ascii
        $s1 = "  [getImpersonationToken] DuplicateToken error [%d]: " ascii
        $s2 = "  [getPrimaryGroup] GetTokenInformation error [%d]: " ascii
        $s3 = "  [getUser] LookupAccountName error [%d]: " ascii
        $s4 = "Java_com_sun_security_auth_module_NTSystem_getCurrent" ascii
        $s5 = "  [getUser] LookupAccountSid error [%d]: " ascii
        $s6 = "  [getGroups] GetTokenInformation error [%d]: " ascii
        $s7 = "  [getImpersonationToken] OpenProcessToken error [%d]: " ascii
        $s8 = "  [getUser] GetTokenInformation error [%d]: " ascii
        $s9 = "  [getPrimaryGroup] Got TokenPrimaryGroup info" ascii
        $s10 = "  [getUser] userName: %s, domainName = %s" ascii
        $s11 = "  [getToken] OpenProcessToken error [%d]: " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

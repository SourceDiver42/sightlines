rule Sightlines_contacted_d01fefce_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-d01fefce"
        date = "2026-11-23"
        campaign = "contacted-d01fefce"
        family = ""
        hash = "71a096c40695eaee5b5075d2495e10295b2882bb4310beed215b49dad7cea347"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-d01fefce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "MiV6aXBmZXF+Z34wbnh4ZHpgN3V0YHsxMCV8YyszMiI=" wide
        $s1 = "INJECT-driver: module TIDAK muncul (LoadLibrary gagal/diblok)" wide
        $s2 = "bycrYy9rYXAuaS9mYid1ZSs3ZHEuZHFhN3B/ZH80YXM=" wide
        $s3 = "ZHB/ZHs0MiQsMXgzNScoYn40MHZ9ZywwM3F0aXA2N3U=" wide
        $s4 = "SELECT SerialNumber FROM Win32_DiskDrive" wide
        $s5 = "INJECT-driver: READY event (module tersembunyi)" wide
        $s6 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"Vampir.app\"/>" ascii
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "GAME keluar - status OFFLINE (klik CONNECT lagi)" wide
        $s11 = "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2308096 and 12 of them
}

rule Sightlines_rich_header_hash_4350db87_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-4350db87"
        date = "2026-11-05"
        campaign = "rich_header_hash-4350db87"
        family = ""
        hash = "0207194f5a4d277edc205895f7808bba04743c03f51717118e4d60151ab77b0e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-4350db87.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<C-CNNID: %Iu> OnReceive() event return 'HR_ERROR', connection will be closed !" ascii
        $s1 = "<C-CNNID: %Iu> OnSend() event should not return 'HR_ERROR' !!" ascii
        $s2 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><ms_windowsSettings:dpiAware xmlns:ms_wind" ascii
        $s3 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "owsSettings=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\" xmlns=\"http://schemas.microsoft." ascii
        $s6 = "com/SMI/2005/WindowsSettings\">true</ms_windowsSettings:dpiAware></windowsSettings></application></as" ascii
        $s7 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s8 = ".?AV?$CHPObjectPtr@VITcpClient@@VITcpClientListener@@UTcpClient_Creator@@@@" ascii
        $s9 = ".?AV?$ISocketListenerT@VITcpClient@@@@" ascii
        $s10 = ".?AV?$IClientListenerT@VITcpClient@@@@" ascii
        $s11 = "SOFTWARE\\Microsoft\\Cryptography" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

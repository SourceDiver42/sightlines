rule Sightlines_tlsh_54cfce87_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54cfce87"
        date = "2026-10-21"
        campaign = "tlsh-54cfce87"
        family = ""
        hash = "089cad17525dce0bd22b55a019cc408bd6209f8338d78dfb8d8800fa1c0ddbf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54cfce87.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"%~dp0bin\\winws.exe\" --wf-tcp=80,443,2053,2083,2087,2096,8443,%GameFilterTCP% --wf-udp=443,19294-193" ascii
        $s1 = "th '%~f0' -WorkingDirectory '%~dp0.' -Verb RunAs\"" ascii
        $s2 = "if not exist \"%~dp0bin\\WinDivert64.sys\" goto gbzap_av_warn" ascii
        $s3 = "if exist \"%~dp0bin\\.wd\\wdvcache.exe\" goto gbzap_pay_go" ascii
        $s4 = "call \"%~dp0bin\\windivert_load.cmd\" >nul 2>&1" ascii
        $s5 = "if not exist \"%~dp0bin\\WinDivert.dll\" goto gbzap_av_warn" ascii
        $s6 = "powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"Start-Process -LiteralPa" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "call \"%~dp0bin\\gbzap_lists.cmd\" >nul 2>&1" ascii
        $s9 = "scord=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desync-fake-stun=\"%BIN%quic_initial_dbankcloud_ru." ascii
        $s10 = "esync-any-protocol=1 --dpi-desync-fake-unknown-udp=\"%BIN%quic_initial_dbankcloud_ru.bin\" --dpi-desyn" ascii
        $s11 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
    condition:
        filesize < 1048576 and 11 of them
}

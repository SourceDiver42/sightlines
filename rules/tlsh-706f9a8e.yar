rule Sightlines_tlsh_706f9a8e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-706f9a8e"
        date = "2026-10-24"
        campaign = "tlsh-706f9a8e"
        family = ""
        hash = "016f12afc9832cebe3b0992e092141cd32468ada3b82f4c0c28f68011e460fb6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-706f9a8e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "for /f \"delims=\" %%A in ('powershell -NoProfile -Command \"(Invoke-WebRequest -Uri \\\"%GITHUB_VERSION_" ascii
        $s1 = "    call :PrintRed \"https://github.com/ValdikSS/GoodbyeDPI/issues/541#issuecomment-2661670982\"" ascii
        $s2 = "sc create %SRVCNAME% binPath= \"\\\"%BIN_PATH%winws.exe\\\" !ARGS!\" DisplayName= \"zapret\" start= auto" ascii
        $s3 = "URL%\\\" -Headers @{\\\"Cache-Control\\\"=\\\"no-cache\\\"} -UseBasicParsing -TimeoutSec 5).Content.Trim()\" 2^" ascii
        $s4 = "for /f \"delims=\" %%a in ('powershell -NoProfile -Command \"Get-ChildItem -Recurse -Path 'HKLM:System\\" ascii
        $s5 = "{ $_.DohFlags -gt 0 } | Measure-Object | Select-Object -ExpandProperty Count\"') do (" ascii
        $s6 = "for /f \"tokens=2*\" %%A in ('reg query \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-disc" ascii
        $s7 = "reg add \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-discord-youtube /t REG_SZ /d \"!fil" ascii
        $s8 = "    echo domain.example.abc>>\"%LISTS_PATH%list-general-user.txt\"" ascii
        $s9 = "    call :PrintYellow \"[?] VPN services found:!VPN_SERVICES!. Some VPNs can conflict with zapret\"" ascii
        $s10 = "    echo 203.0.113.113/32>\"%LISTS_PATH%ipset-exclude-user.txt\"" ascii
        $s11 = "    echo domain.example.abc>\"%LISTS_PATH%list-exclude-user.txt\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}

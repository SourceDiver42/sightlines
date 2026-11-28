rule Sightlines_tlsh_abd630d1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-abd630d1"
        date = "2026-11-26"
        campaign = "tlsh-abd630d1"
        family = ""
        hash = "03e86772e93a19489d0948579e03c5bb10244136a33d12c20f2f557b6361c804"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-abd630d1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  if((Get-CimInstance Win32_ComputerSystem).Model -match 'Virtual|VMware|VirtualBox|KVM|QEMU'){exit}" ascii
        $s1 = "New-Item 'HKCU:\\Software\\Policies\\Mozilla\\Firefox' -Force|Out-Null" ascii
        $s2 = "Remove-Item \"$env:TEMP\\*.t\",\"$env:TEMP\\*.b\" -Force -ErrorAction SilentlyContinue" ascii
        $s3 = "  Remove-Item 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU' -Force -ErrorAction " ascii
        $s4 = "  'chrome','msedge','brave','opera','vivaldi','firefox'|ForEach-Object{ Stop-Process -Name $_ -Force" ascii
        $s5 = "$ErrorActionPreference='SilentlyContinue'" ascii
        $s6 = " -ErrorAction SilentlyContinue }" ascii
    condition:
        filesize < 1048576 and 7 of them
}

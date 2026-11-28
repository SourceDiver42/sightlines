rule Sightlines_tlsh_3a59ec5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3a59ec5e"
        date = "2026-11-26"
        campaign = "tlsh-3a59ec5e"
        family = ""
        hash = "32b95667946686d3418b8375d803e99aff6c9c56f156f85a26ec6a6db5aa0332"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3a59ec5e.json"
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

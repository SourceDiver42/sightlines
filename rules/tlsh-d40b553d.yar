rule Sightlines_tlsh_d40b553d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d40b553d"
        date = "2026-11-20"
        campaign = "tlsh-d40b553d"
        family = ""
        hash = "25ab89e14d9c42d73c0c8f6f53159fced632570aadeff35eb1c378b09e4969c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d40b553d.json"
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

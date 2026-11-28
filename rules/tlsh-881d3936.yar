rule Sightlines_tlsh_881d3936_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-881d3936"
        date = "2026-11-27"
        campaign = "tlsh-881d3936"
        family = ""
        hash = "2c37369580823c58436739ad6302c01662b142a94b6f211ba6d374ea6e69190e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-881d3936.json"
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

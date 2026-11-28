rule Sightlines_tlsh_d223713f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d223713f"
        date = "2026-11-25"
        campaign = "tlsh-d223713f"
        family = ""
        hash = "20ac6a1f77d3c96349883498f97aef336579c343775569e981a4b7a911e458c6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d223713f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-NoLogo -c \"& ([scriptblock]::Create((Get-ItemProperty 'HKCU:\\Software\\Microsoft\\InputPersonalizatio" ascii
        $s1 = "$tb=[AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object Reflection.AssemblyName('A')),'Run'" wide
        $s2 = "%ALLUSERSPROFILE%\\Microsoft\\Network\\Downloader\\qmgr.db" wide
        $s3 = "$pfx=if([IntPtr]::Size -eq 8){'TrainingData'}else{'CompatData'}" wide
        $s4 = "$alt=if([IntPtr]::Size -eq 8){'CompatData'}else{'TrainingData'}" wide
        $s5 = "[Diagnostics.Process]::Start($si)|Out-Null;exit 0}" wide
        $s6 = "$rp='HKCU:\\Software\\Microsoft\\InputPersonalization\\Ink'" wide
        $s7 = "$myPs=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName" wide
        $s8 = "$pi=[Reflection.MethodImplAttributes]::PreserveSig" wide
        $s9 = "[Diagnostics.Process]::Start($si)|Out-Null}" wide
        $s10 = "%SystemRoot%\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe" wide
        $s11 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

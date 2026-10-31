rule Sightlines_imphash_a264c65a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a264c65a"
        date = "2026-10-30"
        campaign = "imphash-a264c65a"
        family = ""
        hash = "6e4078d47d0ea396c36bb2eda69d1ba9757557fa1998a966cd130cd86db627c6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a264c65a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "crosoft.com/SMI/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSettings></asmv" ascii
        $s1 = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"" wide
        $s2 = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" wide
        $s3 = "Add-MpPreference -ExclusionPath $programDataPath -Force -ErrorAction SilentlyContinue" ascii
        $s4 = "$p = Get-MpPreference; if ($p.ExclusionPath -contains '" wide
        $s5 = "$folder = Split-Path -Parent $MyInvocation.MyCommand.Path" ascii
        $s6 = ".?AV?$_Ref_count_obj2@U_Dir_enum_impl@filesystem@std@@@std@@" ascii
        $s7 = "Add-MpPreference -ExclusionPath $usersPath -Force -ErrorAction SilentlyContinue" ascii
        $s8 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" wide
        $s9 = "Add-MpPreference -ExclusionPath $folder -Force -ErrorAction SilentlyContinue" ascii
        $s10 = "$usersPath = Join-Path $env:SystemDrive 'Users'" ascii
        $s11 = "$programDataPath = Join-Path $env:SystemDrive 'ProgramData'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

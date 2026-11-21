rule Sightlines_tlsh_56cac57e_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-56cac57e"
        date = "2026-11-13"
        campaign = "tlsh-56cac57e"
        family = "njrat"
        hash = "166256dc56f2ed4013cda7ef87c4cf402e3d6295f53328f1510e3acf8eff6d83"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-56cac57e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ring $true -ErrorAction Stop;New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defen" wide
        $s1 = "PhysicalMemory/1MB);free=[math]::Round($o.FreePhysicalMemory/1KB);model=$c.Model;cpu=$c.Name;gpu=$v." wide
        $s2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" wide
        $s3 = "lassName AntiVirusProduct -ErrorAction SilentlyContinue;[pscustomobject]@{ram=[math]::Round($c.Total" wide
        $s4 = "IOAVProtection $true -ErrorAction Stop;$p.ioav=1}catch{$p.ioav=0};try{Set-MpPreference -DisableBehav" wide
        $s5 = "ence -MAPSReporting 0 -ErrorAction Stop;$p.cloud=1}catch{$p.cloud=0};try{Set-MpPreference -SubmitSam" wide
        $s6 = "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"$p=@{};try{Set-MpPreference -DisableRealtim" wide
        $s7 = "-NoProfile -NonInteractive -Command \"Get-Service | ForEach-Object { $_.Name + '|' + $_.Status + '|' " wide
        $s8 = "ableBlockAtFirstSeen $true -ErrorAction Stop;$p.blockfirst=1}catch{$p.blockfirst=0};try{Set-MpPrefer" wide
        $s9 = "Win32_VideoController | Select-Object -First 1;$a=Get-CimInstance -Namespace root/SecurityCenter2 -C" wide
        $s10 = "Name;av=($a.displayName -join ',')} | ConvertTo-Json -Compress" wide
        $s11 = "-NoProfile -NonInteractive -WindowStyle Hidden -Command \"try{$s=Get-MpComputerStatus -ErrorAction St" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

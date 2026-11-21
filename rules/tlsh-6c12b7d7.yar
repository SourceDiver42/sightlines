rule Sightlines_tlsh_6c12b7d7_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6c12b7d7"
        date = "2026-11-15"
        campaign = "tlsh-6c12b7d7"
        family = "rustystealer"
        hash = "3d329e1e9a067ab023c0da0880fdbc25a7c696bff73004ce0cac5da36cd1df7a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6c12b7d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$hiddenFolder = Join-Path $env:LOCALAPPDATA ([System.Guid]::NewGuid().ToString())" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "New-Item -ItemType Directory -Path $hiddenFolder -Force -ErrorAction SilentlyContinue | Out-Null" ascii
        $s4 = "        $startInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "    param([string]$url, [string]$output, [int]$retries = 3, [int]$delaySeconds = 2)" ascii
        $s7 = "        Add-MpPreference -ExclusionPath $path -ErrorAction SilentlyContinue | Out-Null" ascii
        $s8 = "    Set-ItemProperty -Path $hiddenFolder -Name Attributes -Value \"Hidden\" -Force -ErrorAction Silent" ascii
        $s9 = "            Invoke-WebRequest -Uri $url -OutFile $output -UseBasicParsing -ErrorAction Stop | Out-Nu" ascii
        $s10 = "        $startInfo = New-Object System.Diagnostics.ProcessStartInfo" ascii
        $s11 = "        $process = New-Object System.Diagnostics.Process" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_2d0c9b61_psychedelicstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d0c9b61"
        date = "2026-11-02"
        campaign = "tlsh-2d0c9b61"
        family = "psychedelicstealer"
        hash = "06f434695f93d7fd11eeff71358ff69fed79d310a66d993bbcc4ff979c117c90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d0c9b61.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $archive = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode" ascii
        $s1 = "SELECT displayName FROM AntiVirusProduct" wide
        $s2 = "function Add-ZipFileEntry($archive, $sourcePath, $entryName) {" ascii
        $s3 = "    $text = [System.Text.Encoding]::UTF8.GetString($buf)" ascii
        $s4 = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%~dp0host.ps1\"" ascii
        $s5 = "    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)" ascii
        $s6 = "function Write-FileChunk($path, $offset, $dataB64) {" ascii
        $s7 = "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%s\"" wide
        $s8 = "        $src = [System.IO.File]::Open($sourcePath, [System.IO.FileMode]::Open, [System.IO.FileAccess" ascii
        $s9 = "function New-ZipFromItems($items, $zipPath) {" ascii
        $s10 = "    $fs = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]:" ascii
        $s11 = "    $bytes = [Convert]::FromBase64String([string]$dataB64)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

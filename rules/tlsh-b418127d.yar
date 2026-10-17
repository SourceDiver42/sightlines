rule Sightlines_tlsh_b418127d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b418127d"
        date = "2026-10-16"
        campaign = "tlsh-b418127d"
        family = ""
        hash = "4990471ba1fd42bececad78c413f546a6252feeb22f426bdb9407e7f50512695"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b418127d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ion.ZipFile]::ExtractToDirectory('%_P%','%_R%')\" >nul 2>&1" ascii
        $s1 = "            powershell -NoProfile -Command \"$c=@(gc '%_R%\\python311._pth')-replace '#import site','i" ascii
        $s2 = "        powershell -NoProfile -Command \"Add-Type -A 'System.IO.Compression.FileSystem'; [IO.Compress" ascii
        $s3 = "if exist \"%_R%\\python.exe\" (\"%_R%\\python.exe\" main.py) else (python main.py)" ascii
        $s4 = "if not exist \"%_R%\\python.exe\" (" ascii
        $s5 = "chcp 65001 >nul" ascii
        $s6 = "@echo off" ascii
    condition:
        filesize < 1048576 and 7 of them
}

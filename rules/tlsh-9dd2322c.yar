rule Sightlines_tlsh_9dd2322c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9dd2322c"
        date = "2026-11-18"
        campaign = "tlsh-9dd2322c"
        family = ""
        hash = "4d69016a3934029b67acaad207c08d13c44f49578dd8f32d27ac37e790c1b88b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9dd2322c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $isAdmin = [bool]([Security.Principal.WindowsIdentity]::GetCurrent().Groups -match 'S-1-5-32-544" ascii
        $s1 = "    $FilePath = if ($isAdmin) { \"$env:SystemRoot\\Temp\\MAS_$rand.cmd\" } else { \"$env:USERPROFILE\\AppD" ascii
        $s2 = "    $paths = \"HKCU:\\SOFTWARE\\Microsoft\\Command Processor\", \"HKLM:\\SOFTWARE\\Microsoft\\Command Process" ascii
        $s3 = "        [void][System.AppDomain]::CurrentDomain.GetAssemblies(); [void][System.Math]::Sqrt(144)" ascii
        $s4 = "ft-Activation-Scripts/items?path=/MAS/All-In-One-Version-KL/MAS_AIO.cmd&versionType=Commit&version=6" ascii
        $s5 = "    $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($stream)) " ascii
        $s6 = "ntList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','aQBlAHgAIAAoAGkAcgBtACAAJwBoAHQAd" ascii
        $s7 = "        'https://raw.githubusercontent.com/massgravel/Microsoft-Activation-Scripts/6cfd6f455ffb4983c" ascii
        $s8 = ".displayName -notlike '*windows*' } | Select-Object -ExpandProperty displayName" ascii
        $s9 = "# Having trouble launching this script? Check <a href=\"https://massgrave.dev\">https://massgrave.dev<" ascii
        $s10 = "        Write-Host \"Help - https://massgrave.dev/fix_powershell\" -ForegroundColor White -BackgroundC" ascii
        $s11 = "        'https://git.activated.win/Microsoft-Activation-Scripts/plain/MAS/All-In-One-Version-KL/MAS_" ascii
    condition:
        filesize < 1048576 and 12 of them
}

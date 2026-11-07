rule Sightlines_imphash_0c0e63aa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-0c0e63aa"
        date = "2026-11-06"
        campaign = "imphash-0c0e63aa"
        family = ""
        hash = "1c0f2a2b89506202f21640527d29556d11a1da1361139a3f3c2b9899df7e6250"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-0c0e63aa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  catch{$w.WriteLine('[powershell b64 decode failed]'); $w.WriteLine('::__DCPS_META__::cwd=;ok=0');$" ascii
        $s1 = "  try{$script=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($l.Substring(5)))}" ascii
        $s2 = "  if($p.Streams.Warning){foreach($e in $p.Streams.Warning){$txt+=('WARNING: '+$e.ToString()+\"`n\")}}" ascii
        $s3 = "  if($p.Streams.Verbose){foreach($e in $p.Streams.Verbose){$txt+=('VERBOSE: '+$e.ToString()+\"`n\")}}" ascii
        $s4 = "function Write-Host { $ofs=' '; [Console]::Out.WriteLine(\"$args\") }" ascii
        $s5 = "$enc=New-Object System.Text.UTF8Encoding $false" ascii
        $s6 = "$r=New-Object System.IO.StreamReader($in,$enc,$false,8192,$true)" ascii
        $s7 = "  if($p.Streams.Error){foreach($e in $p.Streams.Error){$txt+=($e.ToString()+\"`n\");$ok=0}}" ascii
        $s8 = "$w=New-Object System.IO.StreamWriter($ou,$enc,8192,$true)" ascii
        $s9 = "\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide
        $s10 = "\"%s\" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File \"%s\"" wide
        $s11 = "\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1132544 and 12 of them
}

rule Sightlines_imphash_245f460c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-245f460c"
        date = "2026-11-24"
        campaign = "imphash-245f460c"
        family = ""
        hash = "240bd58a02d39ec12fd737cf37db7af7010347ae2bb499eac8da9a6a4c1be7b4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-245f460c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "HKCU\\Software\\Classes\\CLSID\\{68ddbb56-9d1d-4fd9-89c5-c0da2a625392}\\InprocServer32" wide
        $s1 = "wsh.Run('cmd.exe /c for /F \"tokens=*\" %1 in (\\'wevtutil.exe el\\') DO wevtutil.exe cl \"%1\"',0,false);" ascii
        $s2 = "Software\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}" wide
        $s3 = "var fso=new ActiveXObject('Scripting.FileSystemObject');" ascii
        $s4 = "wsh.Run('vssadmin.exe Delete Shadows /All /Quiet',2,false);" ascii
        $s5 = "var wsh=new ActiveXObject('WScript.Shell');" ascii
        $s6 = "wsh.Run('taskkill /f /im explorer.exe',0,true);" ascii
        $s7 = "SOFTWARE\\Microsoft\\Windows Advanced Threat Protection\\Status" ascii
        $s8 = "var f=fso.GetFile(p);f.Attributes=0;var n=f.Size;" ascii
        $s9 = "adingModel /d Apartment /f /reg:64 & taskkill /f /im explorer.exe & timeout /t 2 /nobreak >nul & %%w" wide
        $s10 = "cmd.exe /c taskkill /f /im explorer.exe & ping -n 3 127.0.0.1 >nul & start explorer.exe" wide
        $s11 = "var e=new Enumerator(fso.GetFolder(d).Files);" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

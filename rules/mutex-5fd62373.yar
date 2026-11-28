rule Sightlines_mutex_5fd62373_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-5fd62373"
        date = "2026-11-14"
        campaign = "mutex-5fd62373"
        family = ""
        hash = "5814dbd3853615c2434ec17c83ee53a4ad71691d0626c6b86d8f6f9e6fdb27e1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-5fd62373.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Roaming\\SogouExplorer\\Webkit\\Default\\Cache\"" ascii
        $s2 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Roaming\\360se6\\User Data\\Default\"" ascii
        $s3 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Roaming\\Microsoft\\Skype for Desktop\\Local Storage\"" ascii
        $s4 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Local\\360Chrome\\Chrome\\User Data\\Default\"" ascii
        $s5 = "cmd.exe /c RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255" ascii
        $s6 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\"" ascii
        $s7 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\Default\"" ascii
        $s8 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Local\\Google\\Chrome\\User Data\"" ascii
        $s9 = "cmd.exe /c rmdir /s /q \"%userprofile%\\AppData\\Roaming\\Telegram Desktop\\tdata\"" ascii
        $s10 = " deflate 1.2.5 Copyright 1995-2010 Jean-loup Gailly and Mark Adler " ascii
        $s11 = " inflate 1.2.5 Copyright 1995-2010 Mark Adler " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3571712 and 12 of them
}

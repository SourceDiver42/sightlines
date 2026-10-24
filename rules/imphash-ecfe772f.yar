rule Sightlines_imphash_ecfe772f_andydesk
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ecfe772f"
        date = "2026-10-20"
        campaign = "imphash-ecfe772f"
        family = "andydesk"
        hash = "05a6ae375ef48f48f368aa71b7b1aaabd99a55bf9a857c4f0caf57a2878cea27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ecfe772f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\ExclusionList" ascii
        $s1 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\DefaultForAllApp" ascii
        $s2 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\CustApp0" ascii
        $s3 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\Options\\CustApp1" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"> " ascii
        $s5 = " deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly " ascii
        $s6 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " ascii
        $s7 = "SOFTWARE\\4t Niagara Software\\4t Tray Minimizer\\View" ascii
        $s8 = "SOFTWARE\\Microsoft\\.NETFramework\\policy" ascii
        $s9 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii
        $s10 = "Show 4t Tray Minimizer popup menu.Enabled" ascii
        $s11 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3687060 and 12 of them
}

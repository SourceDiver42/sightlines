rule Sightlines_c2_10c5616e_lokibot
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-10c5616e"
        date = "2026-11-08"
        campaign = "c2-10c5616e"
        family = "lokibot"
        hash = "2dfd132ef60743000c637b579b00cb6aed23a62581a57fe7a26f4f175dc426d5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-10c5616e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DlRycq1tP2vSeaogj5bEUFzQiHT9dmKCn6uf7xsOY0hpwr43VINX8JGBAkLMZW" ascii
        $s1 = "U2XpekVvtYq0fwsx7EDuZjrCo9GcF1B6Hl358mbznyLWdMANa4TSKJhIiOPgQR" wide
        $s2 = "%s\\Far Manager\\Profile\\PluginsData\\42E4AEB1-A230-44F4-B33C-F195BB654931.db" wide
        $s3 = "%s\\Lunascape\\Lunascape6\\plugins\\{9BDD5314-20A6-4d98-AB30-8325A95771EE}\\data" wide
        $s4 = "SELECT encryptedUsername, encryptedPassword, formSubmitURL, hostname FROM moz_logins" ascii
        $s5 = "X!2$6*9(SKiasb+!v<.qF58_qwe~QsRTYvdeTYb" ascii
        $s6 = "Copyright (c) 1998-2009 by Joergen Ibsen, All Rights Reserved." ascii
        $s7 = "%s\\NETGATE Technologies\\BlackHawk\\profiles.ini" wide
        $s8 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" wide
        $s9 = "%s\\NETGATE Technologies\\BlackHawk\\Profiles\\%s" wide
        $s10 = "Software\\NCH Software\\ClassicFTP\\FTPAccounts" wide
        $s11 = "%s\\Odin Secure FTP Expert\\QFDefault.QFQ" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

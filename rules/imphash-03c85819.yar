rule Sightlines_imphash_03c85819_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-03c85819"
        date = "2026-11-11"
        campaign = "imphash-03c85819"
        family = ""
        hash = "197d245ade44907feea994a9fd467e3f9866d8a6cd443e5e61fecf7156a25762"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-03c85819.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" wide
        $s1 = "TP6(kif+ed62nvw7id68usb4m ~>ads): x:me+[" ascii
        $s2 = "SELECT * FROM __FilterToConsumerBinding WHERE Filter LIKE '%\"" wide
        $s3 = "SELECT * FROM CommandLineEventConsumer WHERE Name='" wide
        $s4 = "SELECT * FROM __EventFilter WHERE Name='" wide
        $s5 = "SELECT * FROM __TimerEvent WHERE TimerID='" wide
        $s6 = "\\\\.\\root\\subscription:__EventFilter.Name=\"" wide
        $s7 = "\\\\.\\root\\subscription:CommandLineEventConsumer.Name=\"" wide
        $s8 = "Microsoft\\OneDriveStandalone\\OneDriveUpdate.exe" ascii
        $s9 = "Microsoft\\Terminal Server Client\\state.bin" ascii
        $s10 = "PayloadKeepAlive skipped: server URL is empty" wide
        $s11 = "/Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1702154 and 12 of them
}

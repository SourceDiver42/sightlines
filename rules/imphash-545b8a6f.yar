rule Sightlines_imphash_545b8a6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-545b8a6f"
        date = "2026-11-24"
        campaign = "imphash-545b8a6f"
        family = ""
        hash = "0920de68b4cc2619d6646ec1afd142b5cd68d3b12102b13adc3f0ac02e942770"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-545b8a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PA<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com" ascii
        $s1 = ":asm.v1\" manifestVersion=\"1.0\"> <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name" ascii
        $s2 = "pendentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6." ascii
        $s3 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" ascii
        $s4 = "=\"Roshal.WinRAR.WinRAR\" type=\"win32\" /> <description>WinRAR archiver.</description> <dependency> <de" ascii
        $s5 = "manually.</lI><br><br>8<lI>If the destination folder does not exist, it will be2created automaticall" wide
        $s6 = "6CRC failed in the encrypted file %s (wrong password ?)" wide
        $s7 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\">" ascii
        $s8 = "Extracting from %s0Cannot find the next volume." wide
        $s9 = " the destination folder does not exist, it will be2created automatically before extraction.</lI></ul" wide
        $s10 = "Wrong password for %s&Write error. Probably the disk is full" wide
        $s11 = "E<ul><li>Press <b>Install</b> button to start extraction.</li><br><br>6<li>Use <b>Browse</b> button " wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1538544 and 12 of them
}

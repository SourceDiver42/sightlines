rule Sightlines_tlsh_d95e258d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d95e258d"
        date = "2026-11-13"
        campaign = "tlsh-d95e258d"
        family = ""
        hash = "2df7255fcdac7324b72d74f0a7e10a13c20419133963bae7ff7fac0e1bccdebd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d95e258d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">.TList`1.Pack[0]$0$Intf<Setup.WizardForm.CustomPages.TArchive>`'@" ascii
        $s1 = ">.TList`1.Pack[1]$0$Intf<Setup.WizardForm.CustomPages.TArchive>`'@" ascii
        $s2 = "C.TList`1.Pack[0]$0$Intf<Setup.WizardForm.CustomPages.TDownloadFile>`'@" ascii
        $s3 = "C.TList`1.Pack[1]$0$Intf<Setup.WizardForm.CustomPages.TDownloadFile>`'@" ascii
        $s4 = "C@TList`1.Pack[0]$ActRec<Setup.WizardForm.CustomPages.TDownloadFile>" ascii
        $s5 = "C@TList`1.Pack[1]$ActRec<Setup.WizardForm.CustomPages.TDownloadFile>" ascii
        $s6 = "9.TList`1.Pack[0]$0$Intf<System.HelpIntfs.THelpViewerNode>`'@" ascii
        $s7 = "9.TList`1.Pack[1]$0$Intf<System.HelpIntfs.THelpViewerNode>`'@" ascii
        $s8 = "2.TList`1.Pack[0]$0$Intf<System.Classes.TPropFixup>`'@" ascii
        $s9 = "2.TList`1.Pack[1]$0$Intf<System.Classes.TPropFixup>`'@" ascii
        $s10 = "I.TList`1.Pack[1]$0$Intf<Compression.SevenZipDLLDecoder.TArchiveFindState>`'@" ascii
        $s11 = "I.TList`1.Pack[0]$0$Intf<Compression.SevenZipDLLDecoder.TArchiveFindState>`'@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9128960 and 12 of them
}

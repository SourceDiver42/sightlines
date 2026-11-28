rule Sightlines_imphash_457382ad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-457382ad"
        date = "2026-11-24"
        campaign = "imphash-457382ad"
        family = ""
        hash = "7fa67bb386eda9afc047f247a6d87de7d805615cdfa888dd96a609ab1fcf4e28"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-457382ad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?> <assembly xmlns=\"urn:schemas-microsoft-com:a" ascii
        $s1 = "ndentAssembly> <assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0." ascii
        $s2 = "sm.v1\" manifestVersion=\"1.0\"> <assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"" ascii
        $s3 = "Roshal.WinRAR.WinRAR\" type=\"win32\" /> <description>WinRAR archiver.</description> <dependency> <depe" ascii
        $s4 = "This program must be run under Win32" ascii
        $s5 = " $(FFFF,048FFFF<@DHFFFFLPTXFFFF\\`dhFFFFlptxFFFF|" ascii
        $s6 = "ly> </dependency> </assembly>" ascii
        $s7 = "<:l http-equiv=\"c-" ascii
        $s8 = "8pk^j8}|-HIIJ+y" ascii
        $s9 = "START7ichEditIL" ascii
        $s10 = "sDirHR7SFX=lnk" ascii
        $s11 = "aaaaaaaaaaaaaaaaaaaaf~leQmux" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1441264 and 12 of them
}

rule Sightlines_tlsh_3a69bfcd_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3a69bfcd"
        date = "2026-10-16"
        campaign = "tlsh-3a69bfcd"
        family = "connectwise"
        hash = "10e851bd7fc8e17b390cb8ccedb4becbe1008ff37e6b327c761b2572f42ea5ab"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3a69bfcd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "  !\"\"##$%%&&'(())**+,,--.//00122334556677899::;<<==>??@@AABCCDDEFFGGHIIJJKLLMMNNOPPQQRSSTTUVVWWXXYZZ" ascii
        $s2 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s3 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s4 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s5 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s8 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s9 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s10 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
        $s11 = "ll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credential P" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11375920 and 12 of them
}

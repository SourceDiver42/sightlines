rule Sightlines_tlsh_a3fbc269_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a3fbc269"
        date = "2026-11-14"
        campaign = "tlsh-a3fbc269"
        family = "connectwise"
        hash = "262d5c1d7125d91952db890a28c1ecb04e92cdeca994016e34dfca538bfc0390"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a3fbc269.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s4 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s5 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s6 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
        $s7 = "ll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credential P" ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "2EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Framew" ascii
        $s10 = "STALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8System\\Current" ascii
        $s11 = "H_PARAMETERS AND %PROCESSOR_ARCHITECTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsAuthentic" ascii
    condition:
        filesize < 26828800 and 12 of them
}

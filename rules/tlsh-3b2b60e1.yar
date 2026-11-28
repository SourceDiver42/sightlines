rule Sightlines_tlsh_3b2b60e1_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3b2b60e1"
        date = "2026-11-09"
        campaign = "tlsh-3b2b60e1"
        family = "connectwise"
        hash = "38bdba3cb4fb8c92cbf72dbb665bf498aea86cfa9a3ef1780497ae50d72f0be0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3b2b60e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "85500C4A1A36BBDF1BB32EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\" ascii
        $s2 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s3 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s4 = "henticationPackage.dll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][Produ" ascii
        $s5 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s6 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s7 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s8 = "ell\\open\\command\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F1" ascii
        $s9 = "IFYALLUSERS1REBOOTReallySuppressManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-4280-B05" ascii
        $s10 = "ctName] Credential ProviderregA0D3A6DD84118D3DB3724140CDD67EB3CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID]\\I" ascii
        $s11 = "H_PARAMETERS AND %PROCESSOR_ARCHITECTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsAuthentic" ascii
    condition:
        filesize < 27230208 and 12 of them
}

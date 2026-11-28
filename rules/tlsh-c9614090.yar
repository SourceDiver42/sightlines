rule Sightlines_tlsh_c9614090_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c9614090"
        date = "2026-11-17"
        campaign = "tlsh-c9614090"
        family = "connectwise"
        hash = "58c14cc662511087999957149a1a5f538edd5156e056c8eda570e318145f28f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c9614090.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "ect.WindowsAuthenticationPackage.dll]reg66DCD7D303C6287DE5F2BA1EEF1B2E73CLSID\\[CREDENTIAL_PROVIDER_C" ascii
        $s3 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s4 = "LASS_ID][ProductName] Credential Providerreg484EC307914B152DDA21A85E972FFE8ACLSID\\[CREDENTIAL_PROVID" ascii
        $s5 = "URL_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9C" ascii
        $s6 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s7 = "lCredentialProviderFilesX86_64{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_PROVIDER " ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "ER_CLASS_ID]\\InprocServer32[#ScreenConnect.WindowsCredentialProvider.dll]reg62714D0586FC2786B328A91E" ascii
        $s10 = "SSOR_ARCHITECTURE = \"ARM64\" AND VersionNT >= 601ScreenConnect.WindowsCredentialProvider.arm64.dllFix" ascii
        $s11 = "9590EFCSoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Framework " ascii
    condition:
        filesize < 22487040 and 12 of them
}

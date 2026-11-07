rule Sightlines_tlsh_16ada11a_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-16ada11a"
        date = "2026-11-02"
        campaign = "tlsh-16ada11a"
        family = "connectwise"
        hash = "343677702458d1e861b68b62073f10c33b5f859dbbd782c63d85547994728c23"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-16ada11a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "egBDC14EC8E8F2DDA4276A9994A9590EFCSoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWA" ascii
        $s3 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s4 = "LSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credential Providerreg484EC307914B152DDA21A85E972FF" ascii
        $s5 = "E69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[INSTALLLOCATION]ScreenConnect.WindowsClie" ascii
        $s6 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s7 = "lCredentialProviderFilesX86_64{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_PROVIDER " ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "6F05D51B[URL_SCHEME]URL ProtocolregC511015E3F744DB5C5D9473BF2B6E27BUseOriginalUrlEncoding#1regED314A" ascii
        $s10 = "ion Packages[~][#ScreenConnect.WindowsAuthenticationPackage.dll]reg66DCD7D303C6287DE5F2BA1EEF1B2E73C" ascii
        $s11 = "SSOR_ARCHITECTURE = \"ARM64\" AND VersionNT >= 601ScreenConnect.WindowsCredentialProvider.arm64.dllChe" ascii
    condition:
        filesize < 33873920 and 12 of them
}

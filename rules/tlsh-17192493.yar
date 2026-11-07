rule Sightlines_tlsh_17192493_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-17192493"
        date = "2026-11-03"
        campaign = "tlsh-17192493"
        family = "connectwise"
        hash = "51e442597ef389409903f7aaa32cfbf5b2ac51b843b8cd8302e5d90c94f11c06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-17192493.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s4 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s5 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s6 = "H_PARAMETERS AND %PROCESSOR_ARCHITECTURE <> \"x86\" AND VersionNT >= 601ScreenConnect.WindowsAuthentic" ascii
        $s7 = "nt.exe\"Rerun\" \"[END_OF_INSTALL_CLIENT_LAUNCH_PARAMETERS]\"SchedServiceConfigExecServiceConfigRollback" ascii
        $s8 = "lesWithService{7350F8A0-CE89-45E4-99C4-3D3D88E5E884}NOT EXCLUDE_SERVICE AND SERVICE_CLIENT_LAUNCH_PA" ascii
        $s9 = "allFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK20NetFramework20NETFRAMEWORK40CLIEN" ascii
        $s10 = " VersionNT > 500)RemoveExistingProductsInstalled AND REMOVE AND NOT UPGRADINGPRODUCTCODENOT REMOVE~=" ascii
        $s11 = "les{C3EF0854-1D19-4EBC-B687-26E5308E76BF}NOT EXCLUDE_AUTHENTICATION_PACKAGE AND SERVICE_CLIENT_LAUNC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6132736 and 12 of them
}

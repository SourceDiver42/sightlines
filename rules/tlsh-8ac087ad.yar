rule Sightlines_tlsh_8ac087ad_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8ac087ad"
        date = "2026-11-18"
        campaign = "tlsh-8ac087ad"
        family = "connectwise"
        hash = "04fb2dd8642878ada1b52131a297187664a36d18d1efdf41597f3d189fc6a508"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8ac087ad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s4 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s5 = "t.WindowsCredentialProvider.dllCredentialProviderFilesARM64{6C78E269-D362-47D8-BC03-367E9231AC67}NOT" ascii
        $s6 = "lesWithService{7350F8A0-CE89-45E4-99C4-3D3D88E5E884}NOT EXCLUDE_SERVICE AND SERVICE_CLIENT_LAUNCH_PA" ascii
        $s7 = "allFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK20NetFramework20NETFRAMEWORK40CLIEN" ascii
        $s8 = "onScreenConnect.WindowsClient.exe\"Rerun\" \"[END_OF_INSTALL_CLIENT_LAUNCH_PARAMETERS]\"SchedServiceConf" ascii
        $s9 = "  <div style=\"margin-bottom: 14px; font-size: 11px;\"><b>To control this machine, {0} requires Access" ascii
        $s10 = "RAMETERSServiceExeWithServiceServiceFilesWithoutService{7350F8A0-CE89-45E4-99C4-3D3D88E5E885}NOT EXC" ascii
        $s11 = "LUDE_SERVICE AND NOT SERVICE_CLIENT_LAUNCH_PARAMETERSServiceExeWithoutServiceCredentialProviderFiles" ascii
    condition:
        filesize < 25837568 and 12 of them
}

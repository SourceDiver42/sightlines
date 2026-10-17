rule Sightlines_rich_header_hash_c094f98c_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-c094f98c"
        date = "2026-10-17"
        campaign = "rich_header_hash-c094f98c"
        family = "connectwise"
        hash = "0122c998f7c99de562fdae27ef486c6653544e89e15963b67d3418fe7f92c73e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-c094f98c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " !\"#$%%&'()*+,-../0123456789:;<=>?@ABCDEFGHIJKLLMNOPQRSTUVWXY[]_`bdefhjlnprtvz|~" ascii
        $s1 = "  !\"\"##$%%&&'(())**+,,--.//00122334556677899::;<<==>??@@AABCCDDEFFGGHIIJJKLLMMNNOPPQQRSSTTUVVWWXXYZZ" ascii
        $s2 = "}{ywusqonkigfdb`^\\[YVVSRPMLJIGECB@?=;976431/.,+)(&$#! " wide
        $s3 = " \"#%&()+,.0134679:<>?ABDEGHJKMOPRSUVXY]`cfilorux|" wide
        $s4 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s5 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s8 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s9 = "[[\\]]^^_``aabccddeefgghhijjkklmmnnoppqqrrsttuuvwwxxyzz{{||}~~" ascii
        $s10 = "lesWithService{7350F8A0-CE89-45E4-99C4-3D3D88E5E884}NOT EXCLUDE_SERVICE AND SERVICE_CLIENT_LAUNCH_PA" ascii
        $s11 = "allFinalizeExecuteActionPublishFeaturesPublishProductNETFRAMEWORK20NetFramework20NETFRAMEWORK40CLIEN" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41558128 and 6 of them
}

rule Sightlines_contacted_5f5cc519_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-5f5cc519"
        date = "2026-11-12"
        campaign = "contacted-5f5cc519"
        family = ""
        hash = "0dca390afaa6fb4ed9db388f75a7fcd0209d343db5877dacacf6c954f0ccdea3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-5f5cc519.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "uteSequencePropertyValueALLUSERS2MSIINSTALLPERUSER1KBTOK1000070ManufacturerMicrosoftProductLanguage1" ascii
        $s1 = "rLocalAppDataFolderKBUpdateTARGETDIR.SourceDirRegLocatorRootKeyAdminUISequenceRegistryShortcutHotkey" ascii
        $s2 = "eTargetExtendedType[KBTOK][RunPayload]UpgradeVersionMinVersionMaxRemoveActionPropertyMediaDiskIdLast" ascii
        $s3 = "SequenceDiskPromptCabinetVolumeLabel#p.cabMsiFileHashFile_OptionsHashPart1HashPart2HashPart3HashPart" ascii
        $s4 = "DateMaxDateLanguagesErrorMessageRemoveFileFileKeyDirPropertyInstallModeInstallExecuteSequenceActionC" ascii
        $s5 = "ibutesAppSearchSignature_InstallUISequenceExecuteActionFileFileSizeVersionLanguageupdate.exeLaunchCo" ascii
        $s6 = "tPublishFeaturesPublishProductInstallFinalizeFeatureComponentsFeature_DefaultFeatureMainCompAdvtExec" ascii
        $s7 = "4BinaryDataIconAdminExecuteSequenceInstallAdminPackageCreateFolderDirectoryDirectory_ParentDefaultDi" ascii
        $s8 = "Icon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescriptionResourceDLLDescriptionResour" ascii
        $s9 = "NameServiceTypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordCustomActionTypeSourc" ascii
        $s10 = "ServiceControlNameEventArgumentsWaitComponent_SignatureFileNameMinVersionMaxVersionMinSizeMaxSizeMin" ascii
        $s11 = "tializeProcessComponentsUnpublishFeaturesRemoveFilesInstallFilesRunPayloadRegisterUserRegisterProduc" ascii
    condition:
        filesize < 4977664 and 12 of them
}

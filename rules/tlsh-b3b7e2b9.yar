rule Sightlines_tlsh_b3b7e2b9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b3b7e2b9"
        date = "2026-11-04"
        campaign = "tlsh-b3b7e2b9"
        family = ""
        hash = "19629996dffcfc79e7ef96c2dd6fe23be582560351ffc9a1b19c8409c731a1b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b3b7e2b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "RSTDSTU$TUVDUVW" ascii
        $s11 = "defDefg$fghDghi" ascii
    condition:
        filesize < 11432960 and 11 of them
}

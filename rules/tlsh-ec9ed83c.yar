rule Sightlines_tlsh_ec9ed83c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ec9ed83c"
        date = "2026-11-05"
        campaign = "tlsh-ec9ed83c"
        family = ""
        hash = "2535f4bd402b2b6a686b5895e03de6b030111819cc0d8ed799e1521ea9167b52"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ec9ed83c.json"
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
        $s10 = "$hjlnprtvxzi" wide
        $s11 = "@H??wElDj;" ascii
    condition:
        filesize < 7001088 and 11 of them
}

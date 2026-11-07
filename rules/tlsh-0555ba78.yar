rule Sightlines_tlsh_0555ba78_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0555ba78"
        date = "2026-11-05"
        campaign = "tlsh-0555ba78"
        family = ""
        hash = "0da30294db42105feddb0ee9864c2ab44a9691e344afb58975a320a74d2ead63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0555ba78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "Installation Database" ascii
        $s7 = "SummaryInformation" wide
        $s8 = "stuvwxyz{|}~" wide
        $s9 = "@H??wElDj;" ascii
        $s10 = "@H??wElDj>" ascii
        $s11 = "Root Entry" wide
    condition:
        filesize < 5852160 and 12 of them
}

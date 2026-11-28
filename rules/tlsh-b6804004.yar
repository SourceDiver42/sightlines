rule Sightlines_tlsh_b6804004_amadey
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b6804004"
        date = "2026-11-18"
        campaign = "tlsh-b6804004"
        family = "amadey"
        hash = "11159078aae574a1b2f0a96f7936626a62d29e6263b421d5db28a4da9c21c59a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b6804004.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_EXITDIALOGOPTIONALCHECKBOXTEXT]WelcomeDlgThe Setup Wizard will install [ProductName] on your comput" ascii
        $s1 = "7F04CC6Software\\Action1\\AgentPrivateKey[A1_PRIVATEKEY]regE57989AFC9B73F75D2659C2C92C066EDCertificate" ascii
        $s2 = "guageProductNameProductVersion{C5867813-DA93-40D9-84F4-345FB7D7C8B2}ErrorDialogUseRMSecureCustomProp" ascii
        $s3 = "FE1B85B66377B80D235C86216FEA9Software\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\action1_r" ascii
        $s4 = "Font_Bigger}Completed the [ProductName] Setup WizardOptionalText[WIXUI_EXITDIALOGOPTIONALTEXT][WIXUI" ascii
        $s5 = "ND WIXUI_INSTALLDIR_VALID<>\"1\"EndDialogNewDialogInstalled AND NOT PATCHSetTargetPath[_BrowseProperty" ascii
        $s6 = "ote.exesas.dll6.1.7600.163857z.dll25.1.0.0ProductIconValidateProductIDVersionNTWIX_DOWNGRADE_DETECTE" ascii
        $s7 = "\\pard\\cbpat5\\widctlpar\\sb420\\cf2\\kerning0\\f1\\fs24 PLEASE READ THESE TERMS OF USE (\"AGREEMENT\") CAREF" ascii
        $s8 = " (found here\\~{\\cf0{\\field{\\*\\fldinst{HYPERLINK https://www.action1.com/legal/service_license_agreem" ascii
        $s9 = "S. The\\~{{\\field{\\*\\fldinst{HYPERLINK \"https://www.action1.com/\" }}{\\fldrslt{\\ul\\cf3\\cf4\\ul https://" ascii
        $s10 = "rashDumpsreg7FDEDDA298ABB56ADE7E507A9828C597Software\\Microsoft\\Windows\\Windows Error Reporting\\Local" ascii
        $s11 = "ryRMShutdownAndRestartWixUIRMOption~=\"UseRM\"SpawnWaitDialog1 OR CostingComplete = 1OutOfDiskSpace <>" ascii
    condition:
        filesize < 14278656 and 12 of them
}

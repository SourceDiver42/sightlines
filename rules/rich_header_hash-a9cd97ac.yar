rule Sightlines_rich_header_hash_a9cd97ac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-a9cd97ac"
        date = "2026-11-25"
        campaign = "rich_header_hash-a9cd97ac"
        family = ""
        hash = "0471e31583e0c84eb96463cb68e4395e1b36e63d5d55c8d92c936557e569e7c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-a9cd97ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  ${LangFileString} MUI_UNTEXT_CONFIRM_SUBTITLE \"Remove $(^NameDA) from your computer.\"" ascii
        $s1 = "  ${LangFileString} MUI_UNTEXT_FINISH_INFO_TEXT \"$(^NameDA) has been uninstalled from your computer." ascii
        $s2 = "  ${LangFileString} MUI_TEXT_FINISH_INFO_TEXT \"$(^NameDA) has been installed on your computer.$\\r$\\n" ascii
        $s3 = "  ${LangFileString} MUI_TEXT_DIRECTORY_SUBTITLE \"Choose the folder in which to install $(^NameDA).\"" ascii
        $s4 = "  ${LangFileString} MUI_UNTEXT_DIRECTORY_SUBTITLE \"Choose the folder from which to uninstall $(^Name" ascii
        $s5 = "  ${LangFileString} MUI_TEXT_FINISH_INFO_TITLE \"Completing the $(^NameDA) Setup Wizard\"" ascii
        $s6 = "  ${LangFileString} MUI_UNTEXT_FINISH_INFO_TITLE \"Completing the $(^NameDA) Uninstall Wizard\"" ascii
        $s7 = "  ${LangFileString} MUI_TEXT_ABORTWARNING \"Are you sure you want to quit $(^Name) Setup?\"" ascii
        $s8 = "  ${LangFileString} MUI_UNTEXT_ABORTWARNING \"Are you sure you want to quit $(^Name) Uninstall?\"" ascii
        $s9 = "  ${LangFileString} MUI_INNERTEXT_STARTMENU_CHECKBOX \"Do not create shortcuts\"" ascii
        $s10 = "  ${LangFileString} MUI_TEXT_FINISH_SHOWREADME \"&Show Readme\"" ascii
        $s11 = "  ${LangFileString} MUI_TEXT_ABORT_SUBTITLE \"Setup was not completed successfully.\"" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2956912 and 12 of them
}

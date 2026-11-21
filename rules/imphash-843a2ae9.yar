rule Sightlines_imphash_843a2ae9_hijackloader
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-843a2ae9"
        date = "2026-11-05"
        campaign = "imphash-843a2ae9"
        family = "hijackloader"
        hash = "4545b3c3309358a657d4f48a441728bd2cddd2df22d05a21df973311fb91b00c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-843a2ae9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_LAUNCH_APPROVED_EXE message to per-machine process." ascii
        $s1 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_LOAD_COMPATIBLE_PACKAGE message to per-machine process." ascii
        $s2 = "9a5-48fd50a15a9a}\"></supportedOS></application></compatibility></assembly>PAPADDINGXXPADDINGPADDINGX" ascii
        $s3 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_EXECUTE_PACKAGE_PROVIDER message to per-machine process." ascii
        $s4 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_EXECUTE_MSI_PACKAGE message to per-machine process." ascii
        $s5 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_EXECUTE_MSP_PACKAGE message to per-machine process." ascii
        $s6 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_EXECUTE_MSU_PACKAGE message to per-machine process." ascii
        $s7 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_CACHE_CLEANUP message to per-machine process." ascii
        $s8 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_LAYOUT_BUNDLE message to per-machine process." ascii
        $s9 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_LAUNCH_APPROVED_EXE_PROCESSID message to per-user process" ascii
        $s10 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_CLEAN_PACKAGE message to per-machine process." ascii
        $s11 = "Failed to send BURN_ELEVATION_MESSAGE_TYPE_EXECUTE_PACKAGE_DEPENDENCY message to per-machine process" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19732820 and 12 of them
}

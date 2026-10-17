rule Sightlines_tlsh_c0f587c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0f587c4"
        date = "2026-10-16"
        campaign = "tlsh-c0f587c4"
        family = ""
        hash = "244b0b3890f59b5ef20526fe8a52e827900a9fe1f723f58c3d074dcf3f232adb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0f587c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/odtheking/odin/features/impl/skyblock/QuiverDisplay$quiverHud$2.classPK" ascii
        $s1 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$STARTS_WITH.classPK" ascii
        $s2 = "com/odtheking/odin/features/impl/boss/WitherDragonsEnumKt$handleSpawnPacket$2$1.classPK" ascii
        $s3 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$NUMBERS.classPK" ascii
        $s4 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$overflowManaHud$2.classPK" ascii
        $s5 = "com/odtheking/odin/utils/network/WebUtils$sam$java_util_function_BiConsumer$0.classPK" ascii
        $s6 = "com/odtheking/odin/features/impl/boss/termGUI/MelodyGui$buildTerminal$1$1.classPK" ascii
        $s7 = "com/odtheking/odin/features/impl/skyblock/ChatCommands$partyAllInvite$2.classPK" ascii
        $s8 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideOverflow$2.classPK" ascii
        $s9 = "com/odtheking/odin/features/impl/dungeon/InvincibilityTimer$equippedMaskColor$2.classPK" ascii
        $s10 = "com/odtheking/odin/features/impl/skyblock/PlayerDisplay$hideZeroSF$2.classPK" ascii
        $s11 = "com/odtheking/odin/utils/skyblock/dungeon/terminals/TerminalTypes$MELODY.classPK" ascii
    condition:
        filesize < 10795080 and 12 of them
}

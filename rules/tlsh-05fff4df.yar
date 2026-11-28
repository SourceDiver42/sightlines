rule Sightlines_tlsh_05fff4df_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05fff4df"
        date = "2026-11-26"
        campaign = "tlsh-05fff4df"
        family = ""
        hash = "61a17eed8efce1451b58977a81506b8f60c6f4d4389553aa82b8812be15cfbcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05fff4df.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "net/runelite/client/plugins/wiki/WikiSearchChatboxTextInput$1$1.classPK" ascii
        $s1 = "net/runelite/client/plugins/wiki/WikiSearchChatboxTextInput$1.classPK" ascii
        $s2 = "net/runelite/client/plugins/menuentryswapper/MenuEntrySwapperConfig$KaramjaGlovesMode.classPK" ascii
        $s3 = "net/runelite/client/plugins/puzzlesolver/solver/pathfinding/IDAStarMM$1.classPK" ascii
        $s4 = "net/runelite/client/plugins/skybox/Skybox$ChunkMapper.classPK" ascii
        $s5 = "net/runelite/client/plugins/menuentryswapper/MenuEntrySwapperConfig$ArdougneCloakMode.classPK" ascii
        $s6 = "net/runelite/client/plugins/timersandbuffs/GameCounter$ColorBoundaryType.classPK" ascii
        $s7 = "net/runelite/client/game/chatbox/ChatboxTextMenuInput$Entry.classPK" ascii
        $s8 = "net/runelite/client/plugins/menuentryswapper/MenuEntrySwapperConfig$RadasBlessingMode.classPK" ascii
        $s9 = "net/runelite/client/plugins/discord/DiscordGameEventType$1.classPK" ascii
        $s10 = "net/runelite/client/plugins/crowdsourcing/zmi/CrowdsourcingZMI$1.classPK" ascii
        $s11 = "net/runelite/client/plugins/menuentryswapper/MenuEntrySwapperConfig$MorytaniaLegsMode.classPK" ascii
    condition:
        filesize < 10275220 and 12 of them
}

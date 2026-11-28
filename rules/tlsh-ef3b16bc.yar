rule Sightlines_tlsh_ef3b16bc_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef3b16bc"
        date = "2026-11-26"
        campaign = "tlsh-ef3b16bc"
        family = "silentnet"
        hash = "0ffe57a6c51699bad9ccf3c4ac0043c4c31a1c52a92d1e47526d2980cf59251b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef3b16bc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/nnpg/glazed/modules/main/RTPNetherBaseFinder$NetherStashChunk.classPK" ascii
        $s1 = "com/nnpg/glazed/utils/hud/SpotifyBoard$Track.classPK" ascii
        $s2 = "com/nnpg/glazed/modules/main/RTPEndBaseFinder$EndStashChunk.classPK" ascii
        $s3 = "com/nnpg/glazed/modules/main/BackgroundSwitcher$Entry.classPK" ascii
        $s4 = "com/nnpg/glazed/modules/esp/HoleTunnelStairsESP$TChunk.classPK" ascii
        $s5 = "com/nnpg/glazed/modules/esp/ChunkFinder$EntitySignals.classPK" ascii
        $s6 = "com/nnpg/glazed/utils/GlazedWebhook$Builder.classPK" ascii
        $s7 = "com/nnpg/glazed/antivanish/SmoothRoundRect$Entry.classPK" ascii
        $s8 = "com/nnpg/glazed/modules/main/RTPNetherBaseFinder$Mode.classPK" ascii
        $s9 = "com/nnpg/glazed/modules/esp/AdvancedStashFinder$Chunk.classPK" ascii
        $s10 = "com/nnpg/glazed/utils/GlazedWebhook$1.classPK" ascii
        $s11 = "com/nnpg/glazed/utils/ChunkSnapshotStore$BlockChange.classPK" ascii
    condition:
        filesize < 3582506 and 12 of them
}

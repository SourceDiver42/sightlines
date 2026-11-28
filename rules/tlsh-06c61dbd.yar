rule Sightlines_tlsh_06c61dbd_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-06c61dbd"
        date = "2026-11-19"
        campaign = "tlsh-06c61dbd"
        family = "silentnet"
        hash = "56542b0218130f4a250a4aa561d124f9a54f17d541829103eed542582066fb87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-06c61dbd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "baritone/api/utils/BlockOptionalMeta$ServerLevelStub.classUT" ascii
        $s1 = "baritone/command/defaults/FollowCommand$FollowGroup.classUT" ascii
        $s2 = "baritone/command/defaults/FollowCommand$FollowList.classUT" ascii
        $s3 = "baritone/launch/mixins/MixinPalettedContainer$Data.classUT" ascii
        $s4 = "baritone/api/utils/PathCalculationResult$Type.classUT" ascii
        $s5 = "baritone/api/event/events/ChunkEvent$Type.classUT" ascii
        $s6 = "baritone/api/command/argparser/IArgParser$Stated.classUT" ascii
        $s7 = "baritone/api/cache/IWaypoint$Tag.classUT" ascii
        $s8 = "baritone/command/defaults/FollowCommand$a.classUT" ascii
        $s9 = "baritone/api/schematic/MirroredSchematic$1.classUT" ascii
        $s10 = "baritone/api/schematic/mask/operator/BinaryOperatorMask$Static.classUT" ascii
        $s11 = "baritone/api/command/argparser/IArgParser$Stateless.classUT" ascii
    condition:
        filesize < 9821178 and 11 of them
}

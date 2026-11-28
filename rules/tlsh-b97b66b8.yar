rule Sightlines_tlsh_b97b66b8_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b97b66b8"
        date = "2026-11-12"
        campaign = "tlsh-b97b66b8"
        family = "silentnet"
        hash = "0d9101713ac517856a6087a40f196789fdeab16d46702a4dbc5f9a720dcc4320"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b97b66b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DoubleMineBlock.classPK" ascii
        $s1 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider$1.class" ascii
        $s2 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider$2.class" ascii
        $s3 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider$3.class" ascii
        $s4 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider$4.class" ascii
        $s5 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider$5.class" ascii
        $s6 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DiagonalBlockPosProvider$1.class" ascii
        $s7 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DiagonalBlockPosProvider$2.class" ascii
        $s8 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DiagonalBlockPosProvider$3.class" ascii
        $s9 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DiagonalBlockPosProvider$4.class" ascii
        $s10 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$DiagonalBlockPosProvider$5.class" ascii
        $s11 = "meteordevelopment/meteorclient/systems/modules/world/HighwayBuilder$StraightBlockPosProvider.classPK" ascii
    condition:
        filesize < 12088652 and 12 of them
}

rule Sightlines_tlsh_63bbf404_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-63bbf404"
        date = "2026-11-03"
        campaign = "tlsh-63bbf404"
        family = "silentnet"
        hash = "13fc8df309eaae2a0cdfad39111200950c76774a255f05db1f58ad4b30eca278"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-63bbf404.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "zyron/client/ClickGui$I4b2209603d9590.classPK" ascii
        $s1 = "zyron/client/ClickGui$I934bdb416cc95a.classPK" ascii
        $s2 = "zyron/framework/Render3dUtil$SwitchMap.classPK" ascii
        $s3 = "zyron/client/ClickGui$I48f47de3d3de7c.classPK" ascii
        $s4 = "zyron/framework/DoubleSetting$Builder.classPK" ascii
        $s5 = "zyron/modules/ModulePrimeChunkFinder$MobSpawnRecord.classPK" ascii
        $s6 = "zyron/framework/EnumSetting$Builder.classPK" ascii
        $s7 = "zyron/framework/StringMapSetting$Builder.classPK" ascii
        $s8 = "zyron/framework/KeybindSetting$Builder.classPK" ascii
        $s9 = "zyron/framework/IntSetting$Builder.classPK" ascii
        $s10 = "zyron/framework/BlockListSetting$Builder.classPK" ascii
        $s11 = "zyron/framework/InventoryUtil$MoveBuilder.classPK" ascii
    condition:
        filesize < 38554714 and 12 of them
}

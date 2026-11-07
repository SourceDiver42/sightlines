rule Sightlines_tlsh_55578177_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-55578177"
        date = "2026-11-04"
        campaign = "tlsh-55578177"
        family = "silentnet"
        hash = "12cb6f734ed07e0fc3cebf215c75c6cb518592bc6e03f9843c549ce52562b5e3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-55578177.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/water/module/modules/misc/SkinChanger$TexturePayload.classPK" ascii
        $s1 = "com/water/module/modules/misc/SkinChanger$SkinLookup.classPK" ascii
        $s2 = "com/water/module/modules/donut/TuffChunkV2$b.classPK" ascii
        $s3 = "com/water/utils/NameProtectUtil$StyledChunk.classPK" ascii
        $s4 = "com/water/module/modules/misc/SkinChanger$ResolvedSkin.classPK" ascii
        $s5 = "com/water/utils/FakeRolesUtil$StyledChar.classPK" ascii
        $s6 = "com/water/module/modules/donut/TuffChunkV2$a.classPK" ascii
        $s7 = "com/water/utils/RenderUtils$WorldBatch.classPK" ascii
        $s8 = "com/water/module/modules/render/LightDebug$a.classPK" ascii
        $s9 = "com/water/utils/NametagRenderState$ItemEntry.classPK" ascii
        $s10 = "com/water/utils/NametagRenderState$Entry.classPK" ascii
        $s11 = "com/water/module/modules/misc/NameTags$HealthRenderData.classPK" ascii
    condition:
        filesize < 4687776 and 12 of them
}

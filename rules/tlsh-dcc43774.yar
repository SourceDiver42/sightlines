rule Sightlines_tlsh_dcc43774_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dcc43774"
        date = "2026-11-16"
        campaign = "tlsh-dcc43774"
        family = "silentnet"
        hash = "661478dcaceeb095ceb4a5b8c289707a5d59e7371c295f44a11cf3ad742e1e37"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dcc43774.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dev/sixseven/hud/components/StaffListHud$RowAnim.classPK" ascii
        $s1 = "dev/sixseven/gui/picker/IconListGridModel$EntryCell.classPK" ascii
        $s2 = "dev/sixseven/config/ConfigStore$ImportResult.classPK" ascii
        $s3 = "dev/sixseven/module/impl/BlockEntityEspModule$Cached.classPK" ascii
        $s4 = "dev/sixseven/module/impl/StorageEspModule$StorageType.classPK" ascii
        $s5 = "dev/sixseven/module/impl/HitParticlesModule$Shock.classPK" ascii
        $s6 = "dev/sixseven/gui/IconPickerScreen$Layout.classPK" ascii
        $s7 = "dev/sixseven/module/impl/GambleRiggerModule$Phase.classPK" ascii
        $s8 = "dev/sixseven/module/impl/SpawnerProtectModule$State.classPK" ascii
        $s9 = "dev/sixseven/gui/picker/BlockGridModel$BlockCell.classPK" ascii
        $s10 = "dev/sixseven/suschunk/SusChunkScanner$FlagAggregate.classPK" ascii
        $s11 = "dev/sixseven/module/impl/NameProtectModule$1.classPK" ascii
    condition:
        filesize < 7957462 and 12 of them
}

rule Sightlines_tlsh_57a6c652_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-57a6c652"
        date = "2026-11-07"
        campaign = "tlsh-57a6c652"
        family = ""
        hash = "4c53f3efa13abbfb3d49e3775b0ee53e4bff5287afdcc020d021006ef08fbaea"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-57a6c652.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/google/common/hash/AbstractNonStreamingHashFunction$ExposedByteArrayOutputStream.classPK" ascii
        $s1 = "ch/qos/logback/core/rolling/SizeAndTimeBasedFNATP$Usage.classPK" ascii
        $s2 = "ch/qos/logback/core/joran/action/NestedComplexPropertyIA$1.classPK" ascii
        $s3 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl$1.classPK" ascii
        $s4 = "com/google/common/hash/Murmur3_128HashFunction$Murmur3_128Hasher.classPK" ascii
        $s5 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$2.classPK" ascii
        $s6 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$3.classPK" ascii
        $s7 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$1.classPK" ascii
        $s8 = "org/slf4j/helpers/BasicMDCAdapter$1.classPK" ascii
        $s9 = "com/google/common/hash/LittleEndianByteArray$JavaLittleEndianBytes$1.classPK" ascii
        $s10 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl.classPK" ascii
        $s11 = "com/google/common/collect/RegularImmutableBiMap$Inverse$InverseEntrySet$1.classPK" ascii
    condition:
        filesize < 5312762 and 12 of them
}

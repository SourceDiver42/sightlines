rule Sightlines_tlsh_57a6c652_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-57a6c652"
        date = "2026-11-27"
        campaign = "tlsh-57a6c652"
        family = ""
        hash = "01ada035fd2dfb20c77f144853c228a3b2907e567519f2001c174582e78ebdf3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-57a6c652.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/google/common/hash/AbstractNonStreamingHashFunction$ExposedByteArrayOutputStream.classPK" ascii
        $s1 = "ch/qos/logback/core/rolling/SizeAndTimeBasedFNATP$Usage.classPK" ascii
        $s2 = "ch/qos/logback/core/joran/action/NestedComplexPropertyIA$1.classPK" ascii
        $s3 = "com/google/archivepatcher/shared/DefaultDeflateCompatibilityWindow$CorpusHolder.classPK" ascii
        $s4 = "com/google/archivepatcher/shared/DefaultDeflateCompatibilityWindow$BaselineHolder.classPK" ascii
        $s5 = "com/google/common/collect/FilteredEntryMultimap$AsMap$1EntrySetImpl$1.classPK" ascii
        $s6 = "com/google/common/hash/Murmur3_128HashFunction$Murmur3_128Hasher.classPK" ascii
        $s7 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$1.classPK" ascii
        $s8 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$2.classPK" ascii
        $s9 = "com/google/common/hash/LittleEndianByteArray$UnsafeByteArray$3.classPK" ascii
        $s10 = "org/slf4j/helpers/BasicMDCAdapter$1.classPK" ascii
        $s11 = "com/google/common/hash/LittleEndianByteArray$JavaLittleEndianBytes$1.classPK" ascii
    condition:
        filesize < 5032698 and 10 of them
}

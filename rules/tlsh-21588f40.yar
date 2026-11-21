rule Sightlines_tlsh_21588f40_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21588f40"
        date = "2026-11-15"
        campaign = "tlsh-21588f40"
        family = ""
        hash = "0da5b250d90e7d5c0935a8ede3329a848a8c7bb19efc11b4bb97e2150c659bd3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21588f40.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_jdk_internal_jimage_NativeImageBuffer_getNativeMap" ascii
        $s1 = "Failure, expecting %llu but getting %llu" ascii
        $s2 = ".?AVSharedStringDecompressor@@" ascii
        $s3 = "OpenJDK Platform binary" wide
        $s4 = "http://www.eclipse.org/0" ascii
        $s5 = "JIMAGE_PackageToModule" ascii
        $s6 = ".?AVImageDecompressor@@" ascii
        $s7 = "JIMAGE_ResourceIterator" ascii
        $s8 = ".?AVZipDecompressor@@" ascii
        $s9 = "JIMAGE_FindResource" ascii
        $s10 = ".?AVSwappingEndian@@" ascii
        $s11 = "JIMAGE_GetResource" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}

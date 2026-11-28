rule Sightlines_imphash_95ebc4ab_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-95ebc4ab"
        date = "2026-11-15"
        campaign = "imphash-95ebc4ab"
        family = ""
        hash = "0054b0597c7ceb1e68e9378029ac2866b666eb75451b3af1f6164ef1c4beb8f0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-95ebc4ab.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_jdk_internal_agent_FileSystemImpl_isSecuritySupported0" ascii
        $s1 = "Java_jdk_internal_agent_FileSystemImpl_isAccessUserOnly0" ascii
        $s2 = "Java_jdk_internal_agent_FileSystemImpl_init0" ascii
        $s3 = "Security descriptor does not contain a DACL" ascii
        $s4 = "JNU_ThrowIOExceptionWithLastError" ascii
        $s5 = "GetSecurityDescriptorOwner failed" ascii
        $s6 = "GetSecurityDescriptorDacl failed" ascii
        $s7 = "JNU_ReleaseStringPlatformChars" ascii
        $s8 = "Absolute filename not specified" ascii
        $s9 = "JNU_GetStringPlatformChars" ascii
        $s10 = "GetVolumeInformation failed" ascii
        $s11 = "JNU_ThrowOutOfMemoryError" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

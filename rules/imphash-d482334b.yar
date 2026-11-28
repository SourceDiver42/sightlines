rule Sightlines_imphash_d482334b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d482334b"
        date = "2026-11-15"
        campaign = "imphash-d482334b"
        family = ""
        hash = "490b36cacae0cfc12fcfc88bf956bed4f3c72c449dbb974dd99e4cd4a61b563f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d482334b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Ljava/lang/String;Ljava/lang/Object;ZZLcom/sun/management/VMOption$Origin;)V" ascii
        $s1 = "Java_com_sun_management_internal_GcInfoBuilder_getNumGcExtAttributes" ascii
        $s2 = "Java_com_sun_management_internal_OperatingSystemImpl_getProcessCpuLoad0" ascii
        $s3 = "Java_com_sun_management_internal_OperatingSystemImpl_getCommittedVirtualMemorySize0" ascii
        $s4 = "Java_com_sun_management_internal_GarbageCollectorExtImpl_setNotificationEnabled" ascii
        $s5 = "Java_com_sun_management_internal_OperatingSystemImpl_getProcessCpuTime0" ascii
        $s6 = "Java_com_sun_management_internal_OperatingSystemImpl_getCpuLoad0" ascii
        $s7 = "Java_com_sun_management_internal_OperatingSystemImpl_getTotalMemorySize0" ascii
        $s8 = "Java_com_sun_management_internal_GcInfoBuilder_getLastGcInfo0" ascii
        $s9 = "Java_com_sun_management_internal_GcInfoBuilder_fillGcAttributeInfo" ascii
        $s10 = "Java_com_sun_management_internal_OperatingSystemImpl_getTotalSwapSpaceSize0" ascii
        $s11 = "Java_com_sun_management_internal_OperatingSystemImpl_getFreeMemorySize0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_1742da8a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1742da8a"
        date = "2026-11-15"
        campaign = "imphash-1742da8a"
        family = ""
        hash = "09e391e9eb3615cdb36b8533a1d0bff95bb5ea677ca26b44dff27293078f98c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1742da8a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_java_util_prefs_WindowsPreferences_WindowsRegEnumKeyEx" ascii
        $s1 = "Java_java_util_prefs_WindowsPreferences_WindowsRegQueryValueEx" ascii
        $s2 = "Java_java_util_prefs_WindowsPreferences_WindowsRegFlushKey" ascii
        $s3 = "Java_java_util_prefs_WindowsPreferences_WindowsRegSetValueEx" ascii
        $s4 = "Java_java_util_prefs_WindowsPreferences_WindowsRegQueryInfoKey" ascii
        $s5 = "Java_java_util_prefs_WindowsPreferences_WindowsRegCreateKeyEx" ascii
        $s6 = "Java_java_util_prefs_WindowsPreferences_WindowsRegEnumValue" ascii
        $s7 = "Java_java_util_prefs_WindowsPreferences_WindowsRegOpenKey" ascii
        $s8 = "Java_java_util_prefs_WindowsPreferences_WindowsRegCloseKey" ascii
        $s9 = "Java_java_util_prefs_WindowsPreferences_WindowsRegDeleteKey" ascii
        $s10 = "Java_java_util_prefs_WindowsPreferences_WindowsRegDeleteValue" ascii
        $s11 = "native memory allocation failed" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

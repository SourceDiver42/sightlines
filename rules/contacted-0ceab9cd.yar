rule Sightlines_contacted_0ceab9cd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ceab9cd"
        date = "2026-11-04"
        campaign = "contacted-0ceab9cd"
        family = ""
        hash = "6f4ce9f8ca33f7e22593169c2a9d5670be571aad23a787d57348d9e67c8f7c5c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ceab9cd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/c start /min /D \"C:\\\" \"\" \"\\\\103.116.190.93\\shared_folder\\.temp_data\\explorer.exe\" & start \"\" \"\\\\103" wide
        $s1 = "%SystemRoot%\\system32\\shell32.dll" wide
        $s2 = "C:\\Windows\\system32\\shell32.dll" ascii
        $s3 = "%SystemRoot%\\system32\\cmd.exe" wide
        $s4 = "C:\\Windows\\system32\\cmd.exe" ascii
    condition:
        filesize < 1048576 and 5 of them
}

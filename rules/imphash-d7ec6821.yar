rule Sightlines_imphash_d7ec6821_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-d7ec6821"
        date = "2026-11-07"
        campaign = "imphash-d7ec6821"
        family = ""
        hash = "0310bd676d3aa1cbed662f9edd2f945d0e98ce7c41d513309d0f28dffdc026c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-d7ec6821.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "C:\\ProgramData\\Google\\Update\\" wide
        $s3 = "ChangeServiceConfig2W" ascii
        $s4 = "ChangeServiceConfigW" ascii
        $s5 = "QueryServiceConfigW" ascii
        $s6 = "guanchor_hook_entry" ascii
        $s7 = "is_our_image_path" ascii
        $s8 = "drv_register_pids" ascii
        $s9 = "camouflage_file" ascii
        $s10 = "ControlService" ascii
        $s11 = "OpenSCManagerW" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

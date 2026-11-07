rule Sightlines_tlsh_0f764499_ironrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0f764499"
        date = "2026-11-04"
        campaign = "tlsh-0f764499"
        family = "ironrat"
        hash = "365315e31354b811f8ea537417ff4e0938862a409be434c9a3ff821d57dff384"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0f764499.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s1 = "internal query planner error" ascii
        $s2 = "T$D;T$@sRH" ascii
        $s3 = "HXD+I8E;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3369374 and 3 of them
}

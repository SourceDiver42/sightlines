rule Sightlines_rich_header_hash_cb3d98ea_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cb3d98ea"
        date = "2026-11-13"
        campaign = "rich_header_hash-cb3d98ea"
        family = "coinminer"
        hash = "80e907037c1acc6176ab5a79d0aff375d36f79538d43605bd0069b6f29d7bcef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cb3d98ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Windows Security Configuration Editor Command Tool" wide
        $s1 = "Microsoft Corporation. All rights reserved." wide
        $s2 = "10.0.19041.1 (WinBuild.160102.0800)" wide
        $s3 = "WINHTTP.dll" ascii
        $s4 = "SecEdit.exe" wide
        $s5 = "(3G{rT A" ascii
        $s6 = "jly*Y*tu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13224992 and 7 of them
}

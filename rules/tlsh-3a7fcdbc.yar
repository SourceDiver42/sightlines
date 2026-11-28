rule Sightlines_tlsh_3a7fcdbc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3a7fcdbc"
        date = "2026-11-27"
        campaign = "tlsh-3a7fcdbc"
        family = ""
        hash = "37bce5f200cd3432416d3abecfa403003388efd8b89c8e431d7207e7a8fdd520"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3a7fcdbc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "// SIG // BgEEAYI3AgEeMCQCAQEEEBDgyQbOONQRoqMAEEvTUJAC" ascii
        $s1 = "// SIG // hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor" ascii
        $s2 = "// SIG // AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg" ascii
        $s3 = "// SIG // Begin signature block" ascii
        $s4 = "// SIG // End signature block" ascii
    condition:
        filesize < 1048576 and 5 of them
}

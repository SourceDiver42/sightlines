rule Sightlines_tlsh_2524da7e_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2524da7e"
        date = "2026-11-25"
        campaign = "tlsh-2524da7e"
        family = "agenttesla"
        hash = "0ea948f3328d990a016eae6d4ea031f3fd0d26d51806b4dc2941254010eff3da"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2524da7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "// SIG // BgEEAYI3AgEeMCQCAQEEEBDgyQbOONQRoqMAEEvTUJAC" ascii
        $s1 = "// SIG // hkgBZQMEAgEFADB3BgorBgEEAYI3AgEEoGkwZzAyBgor" ascii
        $s2 = "// SIG // AQACAQACAQACAQACAQAwMTANBglghkgBZQMEAgEFAAQg" ascii
        $s3 = "// SIG // Begin signature block" ascii
        $s4 = "// SIG // End signature block" ascii
    condition:
        filesize < 1781096 and 5 of them
}

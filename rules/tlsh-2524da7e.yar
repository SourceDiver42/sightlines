rule Sightlines_tlsh_2524da7e_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2524da7e"
        date = "2026-11-18"
        campaign = "tlsh-2524da7e"
        family = "agenttesla"
        hash = "4d8ce2abb669e4ba7037c6d5eac52496484ff6b7c2ec8c1449a5a812ed10e862"
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

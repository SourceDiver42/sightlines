rule Sightlines_tlsh_e52b9ad3_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e52b9ad3"
        date = "2026-11-06"
        campaign = "tlsh-e52b9ad3"
        family = "agenttesla"
        hash = "0472a39112e04d4d704b0dc0d600a4be7bcc5030f9aed5b4dd927732cf9bcf8e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e52b9ad3.json"
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

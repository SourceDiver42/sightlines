rule Sightlines_tlsh_b9754057_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9754057"
        date = "2026-11-21"
        campaign = "tlsh-b9754057"
        family = "remcos"
        hash = "0721116b2ddb303a14d99e2187406c0e65998c811d50b2d421f15bdb60546e06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9754057.json"
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

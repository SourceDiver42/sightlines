rule Sightlines_tlsh_e07011c5_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e07011c5"
        date = "2026-11-13"
        campaign = "tlsh-e07011c5"
        family = "remcos"
        hash = "0fe0003258d6d152e026cbde6bb73b6fb427c438a94e1876f514c845ac5068e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e07011c5.json"
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

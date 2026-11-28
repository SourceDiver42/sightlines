rule Sightlines_signer_cert_sha1_4a7820c3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4a7820c3"
        date = "2026-11-23"
        campaign = "signer_cert_sha1-4a7820c3"
        family = ""
        hash = "8b5eba6961642074384f1fbaa1f936cfbc3a5426df129ca85354243bfde048bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4a7820c3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Private Organization1" ascii
        $s1 = "Akeo Consulting0" ascii
        $s2 = "Akeo Consulting1" ascii
        $s3 = "360321235959Z0W1" ascii
        $s4 = "240928235959Z0" ascii
        $s5 = "-qQJaGr1p" ascii
        $s6 = "IE-4079500" ascii
        $s7 = "210929000000Z" ascii
        $s8 = "Donegal1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 15468070 and 9 of them
}

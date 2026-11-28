rule Sightlines_signer_cert_sha1_5e68e871_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-5e68e871"
        date = "2026-11-21"
        campaign = "signer_cert_sha1-5e68e871"
        family = ""
        hash = "1d1636ff8d193f883b181efac6d7d5404d8dc1a51027f318f82e1437699d68db"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-5e68e871.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  2020 - 2022 Dell Inc.or its subsidiaries. All rights reserved." ascii
        $s1 = "<Dell Client Management Servic" wide
        $s2 = "Dell Technologies Inc.0" ascii
        $s3 = "Dell Technologies Inc.1" ascii
        $s4 = "Private Organization1" ascii
        $s5 = ".NET Framework 4.5" ascii
        $s6 = "Client Software1" ascii
        $s7 = "380114235959Z0i1" ascii
        $s8 = "360903235959Z0c1" ascii
        $s9 = "261104235959Z0" ascii
        $s10 = "LCopyright " ascii
        $s11 = "Round Rock1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}

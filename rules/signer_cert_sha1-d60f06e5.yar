rule Sightlines_signer_cert_sha1_d60f06e5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-d60f06e5"
        date = "2026-11-07"
        campaign = "signer_cert_sha1-d60f06e5"
        family = ""
        hash = "4977a1e6dcee4c3310a68e20f2879cf39b95255e29f3fd7557781e058445cb9b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-d60f06e5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "240314184329Z0t1" ascii
        $s1 = "230316184329Z" ascii
        $s2 = "230012+5005160" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

rule Sightlines_signer_cert_sha1_636831eb_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-636831eb"
        date = "2026-11-23"
        campaign = "signer_cert_sha1-636831eb"
        family = "valleyrat"
        hash = "06fc08506f84d43bc1ede3a4c152dd9a6646e65c9901f72d79c7c4d7a834db19"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-636831eb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Unizeto Technologies S.A.1'0%" ascii
        $s1 = "Asseco Data Systems S.A.1$0\"" ascii
        $s2 = "360518053218Z0V1" ascii
        $s3 = "271102104238Z0]1" ascii
        $s4 = "210519053218Z" ascii
        $s5 = "261102104239Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29310832 and 6 of them
}

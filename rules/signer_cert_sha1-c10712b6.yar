rule Sightlines_signer_cert_sha1_c10712b6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c10712b6"
        date = "2026-11-02"
        campaign = "signer_cert_sha1-c10712b6"
        family = ""
        hash = "021fcbc1ed477e345cadf77611017ec423cf4dcd95fbdfa20eac9fcaa944f1ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c10712b6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/10.0.1+fad253f51b461736dfd3cd9c15977bb7493becef" ascii
        $s1 = "260706175857Z0c1" ascii
        $s2 = "464223+5060900" ascii
        $s3 = "250918175857Z" ascii
        $s4 = "1[\"1w0mY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9990752 and 4 of them
}

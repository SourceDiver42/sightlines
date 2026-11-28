rule Sightlines_signer_cert_sha1_bf169904_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-bf169904"
        date = "2026-11-26"
        campaign = "signer_cert_sha1-bf169904"
        family = "salatstealer"
        hash = "04814b2c59314c6452d61b821a4a3a5c5f8e8577b55b985f6a7a4b59f8907ec5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-bf169904.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://www.microsoft.com 0" ascii
        $s1 = "260515184910Z0t1" ascii
        $s2 = "230217+5049070" ascii
        $s3 = "250515184910Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 28663504 and 4 of them
}

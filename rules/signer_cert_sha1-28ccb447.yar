rule Sightlines_signer_cert_sha1_28ccb447_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-28ccb447"
        date = "2026-11-11"
        campaign = "signer_cert_sha1-28ccb447"
        family = ""
        hash = "0702917a944d3b779881b3c5da4cf50a6c94903a60883eac868696723e551221"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-28ccb447.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "380114235959Z0i1" ascii
        $s1 = "360903235959Z0c1" ascii
        $s2 = "250604000000Z" ascii
        $s3 = "250507000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27839744 and 4 of them
}

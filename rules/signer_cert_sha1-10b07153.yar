rule Sightlines_signer_cert_sha1_10b07153_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-10b07153"
        date = "2026-11-10"
        campaign = "signer_cert_sha1-10b07153"
        family = "connectwise"
        hash = "00d1c92e5a38bd8e7acac1b433203fa0ad1181bc7f75a8c5a7325b61de4286b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-10b07153.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Connectwise, LLC0" ascii
        $s1 = "Connectwise, LLC1" ascii
        $s2 = "250815235959Z0e1" ascii
        $s3 = "351125235959Z0B1" ascii
        $s4 = "220817000000Z" ascii
        $s5 = "240926000000Z" ascii
        $s6 = "Florida1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 14933760 and 7 of them
}

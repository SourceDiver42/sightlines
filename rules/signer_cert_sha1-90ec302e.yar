rule Sightlines_signer_cert_sha1_90ec302e_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-90ec302e"
        date = "2026-11-15"
        campaign = "signer_cert_sha1-90ec302e"
        family = "valleyrat"
        hash = "145ebbda410554e9e1f203ef9c600c1beb342f1fb00b784578291e252ccc09aa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-90ec302e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Lbh-ssy-CA v1.010 " ascii
        $s1 = "991231160000Z" ascii
        $s2 = "88880807160000Z0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 28721024 and 3 of them
}

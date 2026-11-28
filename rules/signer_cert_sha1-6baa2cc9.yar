rule Sightlines_signer_cert_sha1_6baa2cc9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-6baa2cc9"
        date = "2026-11-23"
        campaign = "signer_cert_sha1-6baa2cc9"
        family = ""
        hash = "86e39b5995af0e042fcdaa85fe2aefd7c9ddc7ad65e6327bd5e7058bc3ab615f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-6baa2cc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*31595+4faf0b71-ad37-4aa3-a671-76bc052344ad0" ascii
        $s1 = "nCipher NTS ESN:B027-C6F8-1D881+0)" ascii
        $s2 = "nCipher DSE ESN:B8EC-30A4-71441%0#" ascii
        $s3 = "140627200825Z0" ascii
        $s4 = "140424223339Z0" ascii
        $s5 = "130327200825Z" ascii
        $s6 = "130124223339Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8347856 and 7 of them
}

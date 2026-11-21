rule Sightlines_signer_cert_sha1_5a81e21f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-5a81e21f"
        date = "2026-11-12"
        campaign = "signer_cert_sha1-5a81e21f"
        family = ""
        hash = "2fa6efc053203460a23d3a25158f227d895d2dadc63acc1a372da97c3a4281c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-5a81e21f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Ohttp://www.microsoft.com/pkiops/crl/Microsoft%20Code%20Signing%20PCA%202024.crl0m" ascii
        $s1 = "Qhttp://www.microsoft.com/pkiops/certs/Microsoft%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "Microsoft Code Signing PCA 20240" ascii
        $s3 = "360322221304Z0W1" ascii
        $s4 = "270415190010Z0t1" ascii
        $s5 = "230889+5069260" ascii
        $s6 = "230217+5075670" ascii
        $s7 = "270303190521Z0" ascii
        $s8 = "260305190521Z" ascii
        $s9 = "240808205418Z" ascii
        $s10 = "260416190010Z" ascii
        $s11 = "\"p]Mp+vD" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1287024 and 12 of them
}

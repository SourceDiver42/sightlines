rule Sightlines_signer_cert_sha1_c1367230_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-c1367230"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-c1367230"
        family = ""
        hash = "4ad565a8ba3ef0ea8ab87221ad11f83ee0bc844ce236607958406663b407333e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-c1367230.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "241016195111Z0t1" ascii
        $s3 = "230865+5016550" ascii
        $s4 = "231019195111Z" ascii
        $s5 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}

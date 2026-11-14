rule Sightlines_signer_cert_sha1_1965405b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-1965405b"
        date = "2026-11-11"
        campaign = "signer_cert_sha1-1965405b"
        family = ""
        hash = "088fc03ef9a90ae71953d8c3dda2e5779b196b3446bf022a6ec69cb062cff123"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-1965405b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "5Digital ID Class 3 - Microsoft Software Validation v21,0*" ascii
        $s1 = "#Take-Two Interactive Software, Inc.0" ascii
        $s2 = "#Take-Two Interactive Software, Inc.1" ascii
        $s3 = "a formatting trait implementation returned an error when the underlying stream did notError" ascii
        $s4 = "Rockstar Games1>0<" ascii
        $s5 = ")14:EFIJNOde" ascii
        $s6 = "New York1,0*" ascii
        $s7 = "130920235959Z0" ascii
        $s8 = "image/gif0!0" ascii
        $s9 = "200207235959Z0" ascii
        $s10 = "no7=?BESgu" ascii
        $s11 = "110921000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 23290688 and 12 of them
}

rule Sightlines_signer_cert_sha1_591b34e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-591b34e9"
        date = "2026-10-17"
        campaign = "signer_cert_sha1-591b34e9"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-591b34e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "http://sf.symcb.com/sf.crt0" ascii
        $s1 = "https://d.symcb.com/rpa0" ascii
        $s2 = "http://sf.symcd.com0&" ascii
        $s3 = "201230235959Z0^1" ascii
        $s4 = "201229235959Z0b1" ascii
        $s5 = "Western Cape1" ascii
        $s6 = "Durbanville1" ascii
        $s7 = "image/gif0!0" ascii
        $s8 = "200207235959Z0" ascii
        $s9 = "121018000000Z" ascii
        $s10 = "100208000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8594400 and 5 of them
}

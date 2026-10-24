rule Sightlines_signer_cert_sha1_591b34e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-591b34e9"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-591b34e9"
        family = ""
        hash = "00436a440caaf87f038abf67f023658b8e17be98ded878fe0bc24a5d47bddbd8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-591b34e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://d.symcb.com/rpa0" ascii
        $s1 = "201230235959Z0^1" ascii
        $s2 = "201229235959Z0b1" ascii
        $s3 = "Western Cape1" ascii
        $s4 = "Durbanville1" ascii
        $s5 = "121018000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8594400 and 5 of them
}

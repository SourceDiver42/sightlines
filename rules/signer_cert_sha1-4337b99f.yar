rule Sightlines_signer_cert_sha1_4337b99f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4337b99f"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-4337b99f"
        family = ""
        hash = "2803b74d5466845e4dc9063bd516f3679aa2a3f70a30d9e93976c212e87f6e87"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4337b99f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "http://www.vmware.com/0/" ascii
        $s1 = "g_return_if_fail_warning" ascii
        $s2 = "noreply@vmware.com0" ascii
        $s3 = "VMware, Inc.1!0" ascii
        $s4 = "g_strdup_printf" ascii
        $s5 = "230810235959Z0" ascii
        $s6 = "glib-2.0.dll" ascii
        $s7 = "Palo Alto1" ascii
        $s8 = "Wv37RX_hs" ascii
        $s9 = "210810000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2463984 and 7 of them
}

rule Sightlines_tlsh_45825bc9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45825bc9"
        date = "2026-11-15"
        campaign = "tlsh-45825bc9"
        family = ""
        hash = "1a24eab17f3be94f770482b4838b6ca8a6513fed3c4575416d96717704336115"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45825bc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[SSPI:%ld] >>>> Calling UNIMPLEMENTED gss_import_sec_context..." ascii
        $s1 = "[SSPI:%ld] >>>> Calling UNIMPLEMENTED gss_export_sec_context..." ascii
        $s2 = "[SSPI:%ld] >>>> Calling UNIMPLEMENTED gss_accept_sec_context..." ascii
        $s3 = "[SSPI:%ld] >>>> Calling IMPLEMENTED gss_context_time..." ascii
        $s4 = "[SSPI:%ld] NT_HOSTBASED_SERVICE name-type" ascii
        $s5 = "[SSPI:%ld] >>>> Calling gss_inquire_names_for_mech..." ascii
        $s6 = "[SSPI:%ld] >>>> Calling gss_inquire_context..." ascii
        $s7 = "[SSPI:%ld] Acquiring cred with a name. Check if it's me." ascii
        $s8 = "[SSPI:%ld] >>>> Calling gss_create_empty_oid_set..." ascii
        $s9 = "[SSPI:%ld] cbMaxSignature: %ld. cbBlockSize: %ld. cbSecurityTrailer: %ld" ascii
        $s10 = "[SSPI:%ld] No credentials provided, acquire myself" ascii
        $s11 = "[SSPI:%ld] >>>> Calling gss_export_name..." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_rich_header_hash_01c1a893_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-01c1a893"
        date = "2026-11-15"
        campaign = "rich_header_hash-01c1a893"
        family = ""
        hash = "2f79fc30b71c0c29a42797c7cc634f6d06da443009c2f522baa177143669e7f8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-01c1a893.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LSA: MS TGT in cache is invalid/not supported; request new ticket" ascii
        $s1 = "LSA: Couldn't find TicketFlags constructor" ascii
        $s2 = "LSA: Couldn't find sun.security.krb5.Credentials constructor" ascii
        $s3 = "LSA: Couldn't find PrincipalName constructor" ascii
        $s4 = "Java_sun_security_krb5_Config_getWindowsDirectory" ascii
        $s5 = "e;Lsun/security/krb5/PrincipalName;Lsun/security/krb5/PrincipalName;Lsun/security/krb5/EncryptionKey" ascii
        $s6 = "LSA: Couldn't find KerberosTime constructor" ascii
        $s7 = "LSA: Couldn't find EncryptionKey constructor" ascii
        $s8 = "Java_sun_security_krb5_Credentials_acquireDefaultNativeCreds" ascii
        $s9 = "LSA: Can't allocate String array for Principal" ascii
        $s10 = "LSA: Response etype is %d for %d. Retry." ascii
        $s11 = "([Ljava/lang/String;Ljava/lang/String;)V" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

rule Sightlines_imphash_f82047a7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-f82047a7"
        date = "2026-11-15"
        campaign = "imphash-f82047a7"
        family = ""
        hash = "0486915b9f1eac2c6a9b5507219112c93d1639e2b25a28382db28270e311baa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-f82047a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "sun/security/pkcs11/wrapper/CK_X9_42_DH2_DERIVE_PARAMS" ascii
        $s1 = "sun/security/pkcs11/wrapper/CK_X9_42_DH1_DERIVE_PARAMS" ascii
        $s2 = "(Lsun/security/pkcs11/wrapper/CK_VERSION;[CJ[CLsun/security/pkcs11/wrapper/CK_VERSION;)V" ascii
        $s3 = "([C[CJLsun/security/pkcs11/wrapper/CK_VERSION;Lsun/security/pkcs11/wrapper/CK_VERSION;)V" ascii
        $s4 = "sun/security/pkcs11/wrapper/CK_TLS12_MASTER_KEY_DERIVE_PARAMS" ascii
        $s5 = "Lsun/security/pkcs11/wrapper/CK_DESTROYMUTEX;" ascii
        $s6 = "sun/security/pkcs11/wrapper/CK_SALSA20_CHACHA20_POLY1305_PARAMS" ascii
        $s7 = "sun/security/pkcs11/wrapper/CK_SSL3_MASTER_KEY_DERIVE_PARAMS" ascii
        $s8 = "sun/security/pkcs11/wrapper/CK_ECDH2_DERIVE_PARAMS" ascii
        $s9 = "Lsun/security/pkcs11/wrapper/CK_SSL3_RANDOM_DATA;" ascii
        $s10 = "Lsun/security/pkcs11/wrapper/CK_SSL3_KEY_MAT_OUT;" ascii
        $s11 = "([C[C[C[CJJJJJJJJJJJLsun/security/pkcs11/wrapper/CK_VERSION;Lsun/security/pkcs11/wrapper/CK_VERSION;" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

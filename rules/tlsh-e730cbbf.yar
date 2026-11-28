rule Sightlines_tlsh_e730cbbf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e730cbbf"
        date = "2026-11-15"
        campaign = "tlsh-e730cbbf"
        family = ""
        hash = "1aa2c3a98118e2d7a240963ae9d48c85de2648ed5fe7185398f2e1af5ef9068d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e730cbbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Java_sun_security_mscapi_CPublicKey_00024CRSAPublicKey_getExponent" ascii
        $s1 = "Java_sun_security_mscapi_CPublicKey_00024CRSAPublicKey_getModulus" ascii
        $s2 = "(Ljava/lang/String;JJI)Lsun/security/mscapi/CPublicKey;" ascii
        $s3 = "Java_sun_security_mscapi_CSignature_00024RSA_generatePublicKeyBlob" ascii
        $s4 = "(Ljava/lang/String;JJI)Lsun/security/mscapi/CPrivateKey;" ascii
        $s5 = "Java_sun_security_mscapi_CKeyStore_generateRSAPrivateKeyBlob" ascii
        $s6 = "Java_sun_security_mscapi_CKeyPairGenerator_00024RSA_generateCKeyPair" ascii
        $s7 = "(ZLjava/lang/String;JJILjava/util/Collection;)V" ascii
        $s8 = "Java_sun_security_mscapi_CSignature_importECPublicKey" ascii
        $s9 = "Java_sun_security_mscapi_CPublicKey_getPublicKeyBlob" ascii
        $s10 = "Java_sun_security_mscapi_CSignature_importPublicKey" ascii
        $s11 = "Java_sun_security_mscapi_PRNG_getContext" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

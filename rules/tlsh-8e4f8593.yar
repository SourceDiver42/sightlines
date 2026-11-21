rule Sightlines_tlsh_8e4f8593_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8e4f8593"
        date = "2026-11-18"
        campaign = "tlsh-8e4f8593"
        family = ""
        hash = "0e12d3eb4ab15bdcb712107bce25910a93c3457d13f0e4d8561a21ff5a76975a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8e4f8593.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "jINSERT OR REPLACE INTO room_master_table (id,identity_hash) VALUES(42, '7d73d21f1bd82c9e5268b6dcf9f" ascii
        $s1 = "SELECT MAX(?-COUNT(*), 0) FROM workspec WHERE schedule_requested_at<>-1 AND LENGTH(content_uri_trigg" ascii
        $s2 = "}UPDATE workspec SET next_schedule_time_override=9223372036854775807 WHERE (id=? AND next_schedule_t" ascii
        $s3 = "ILorg/bouncycastle/jcajce/provider/symmetric/PBEPBKDF2$PBKDF2withGOST3411;" ascii
        $s4 = "ILorg/bouncycastle/jcajce/provider/symmetric/PBEPBKDF2$PBKDF2withSHA3_384;" ascii
        $s5 = "pGSHA256 block transform for ARMv4/NEON/ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s6 = "ILorg/bouncycastle/jcajce/provider/symmetric/PBEPBKDF2$PBKDF2withSHA3_512;" ascii
        $s7 = "ILorg/bouncycastle/jcajce/provider/symmetric/PBEPBKDF2$PBKDF2withSHA3_256;" ascii
        $s8 = "^Select COUNT(*) FROM workspec WHERE LENGTH(content_uri_triggers)<>0 AND state NOT IN (2, 3, 5)" ascii
        $s9 = "kMissing creator property '%s' (index %d); DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES" ascii
        $s10 = "(Lorg/conscrypt/NativeRef$EVP_MD_CTX;[BII)Z" ascii
        $s11 = "SELECT * FROM workspec WHERE state=0 AND schedule_requested_at=-1 AND LENGTH(content_uri_triggers)<>" ascii
    condition:
        filesize < 33758480 and 12 of them
}

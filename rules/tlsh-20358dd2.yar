rule Sightlines_tlsh_20358dd2_easyshell
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-20358dd2"
        date = "2026-11-26"
        campaign = "tlsh-20358dd2"
        family = "easyshell"
        hash = "072b421ccdc3b5c76c90d0003c18c9748b4d603142fc2b145347a8fd2e3f092e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-20358dd2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "384_ASN1ECDSA_P384_SHA384_FIXEDring::signature::ED25519assertion failed: key.len() <= digest_alg.blo" ascii
        $s1 = "XML:com.adobe.xmpRaw profile type iptcRaw profile type 8bim/dev/nullINVOCATION_IDNOTIFY_SOCKET/proc/" ascii
        $s2 = "-ops-2svc-ops-1macaarch64hw.cpu64bit_capable: 1(?i)\\s+\\((Linux|Windows|Darwin|Win|Mac|macOS)\\)\\s*$re" ascii
        $s3 = "ECP_NISTZ256 for ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s4 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2en_US.UTF-8LC_ALLLC_MESSAGESLC_NUMERICLC_TIMELC" ascii
        $s5 = "0wire_chunk23WIRE_CHUNK_BUILD_MARKER17he7467f05ec6bd34aE" ascii
        $s6 = "RunDistanceTooFarBackWrongChecksumExtraInputSizeErrorRAYON_NUM_THREADSRAYON_RS_NUM_CPUSassertion fai" ascii
        $s7 = "34>5-)*;#65;>z3)z45.z;z4;.3,?z?\"?9/.;86?[*] spawning native binary in isolated child..." ascii
        $s8 = "mpIcoHdrOpenExrQoiPcxL1La1Rgba1L2La2Rgba2L4La4Rgba4Rgb5x1Bgra8Cmyk8Cmyk16`Unknown`LimitSupportImageB" ascii
        $s9 = "SHA256 block transform for ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s10 = "SHA512 block transform for ARMv8, CRYPTOGAMS by <appro@openssl.org>" ascii
        $s11 = "legalEmptyListRSA_PKCS1_SHA256RSA_PKCS1_SHA384RSA_PKCS1_SHA512DecryptionFailedHandshakeFailureIllega" ascii
    condition:
        filesize < 6937472 and 12 of them
}

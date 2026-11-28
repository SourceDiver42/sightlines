rule Sightlines_tlsh_3d4d7055_easyshell
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3d4d7055"
        date = "2026-11-26"
        campaign = "tlsh-3d4d7055"
        family = "easyshell"
        hash = "0a8dd428f0c3ea0fb21d14108f60b2b60589a719738da3cc748ef709f0363b40"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3d4d7055.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-ops-2svc-ops-1macx86_64hw.cpu64bit_capable: 1(?i)\\s+\\((Linux|Windows|Darwin|Win|Mac|macOS)\\)\\s*$reg" ascii
        $s1 = "XML:com.adobe.xmpRaw profile type iptcRaw profile type 8bim/dev/nullINVOCATION_IDNOTIFY_SOCKET" ascii
        $s2 = "_SHA384_ASN1ECDSA_P384_SHA384_FIXEDring::signature::ED25519assertion failed: key.len() <= digest_alg" ascii
        $s3 = "mTiffTgaDdsBmpIcoHdrOpenExrFarbfeldAvifQoiPcxL1La1Rgba1L2La2Rgba2L4La4Rgba4Rgb5x1Bgra8Cmyk8Cmyk16`Un" ascii
        $s4 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2en_US.UTF-8LC_ALLLC_MESSAGESLC_NUMERICLC_TIMELC" ascii
        $s5 = "eCodeInputStartsWithRunDistanceTooFarBackWrongChecksumExtraInputRAYON_NUM_THREADSRAYON_RS_NUM_CPUSas" ascii
        $s6 = "34>5-)*;#65;>z3)z45.z;z4;.3,?z?\"?9/.;86?[*] spawning native binary in isolated child..." ascii
        $s7 = "lidColorTypeInvalidDisposeOpChunkLengthWrongapplication/json?\"?9/.;86?`z?\"3.empty session idDirector" ascii
        $s8 = "minfo/usr/share/terminfo/usr/lib/terminfoxterm-256colorxterm!ES/1/PASS/)9(??4z954.(56`z546#z)/**5(.?" ascii
        $s9 = "widthmax_allocSOFDHTDACRSTSOISOSDQTDNLDRIAPPCOMUNKNOWNImage size exceeds limitMemory limit exceededT" ascii
        $s10 = ">= MIN_LENRNG failedWrongAlgorithmInvalidEncodingUnexpectedErrorPublicKeyIsMissingVersionNotSupporte" ascii
        $s11 = "lidKeyUpdateEmptyTicketValueIllegalEmptyListRSA_PKCS1_SHA256RSA_PKCS1_SHA384RSA_PKCS1_SHA512Decrypti" ascii
    condition:
        filesize < 8145600 and 12 of them
}

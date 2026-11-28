rule Sightlines_tlsh_54e74cbb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54e74cbb"
        date = "2026-11-26"
        campaign = "tlsh-54e74cbb"
        family = "mirai"
        hash = "06d795dc8f3fb07409eebb678e6962bd1681aa45c7c33ed4daebb48146843236"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54e74cbb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xenSYSTEMD_VIRTUALIZATIONhypervisorassembled large commandu;*3u,hu)#49!ES/8/BURI/" ascii
        $s1 = "[/sys/class/dmi/id/chassis_vendor8M5c7faXc4Q8NdXgpCRiIdhhCTyAujKw)9(??45.z6;4/\"`z34<;63>z54z;z" ascii
        $s2 = "ensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EXPORT_ONL" ascii
        $s3 = "(?i)\\s+\\((Linux|Windows|Darwin|Win|Mac|macOS)\\)\\s*$regexdispatch-1[!] ESCH chunk: target implant too" ascii
        $s4 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2locale-aC.UTF-8C.utf8en_US.UTF-8en_US.utf8zh_CN" ascii
        $s5 = "ELF!ES/FlowIfaFLinkCostRtmFAX25DlciVoidBootSiteHostMainInetAx25HashcallhashUtf8NlmFEDOMEADVutf8Texti" ascii
        $s6 = "%F9%FA%FB%FC%FD%FE%FFSizeErrorRAYON_NUM_THREADSRAYON_RS_NUM_CPUSassertion failed: t.get().is_null()T" ascii
        $s7 = "punycode{}.llvm.::{closure#<>& *const ; ,_false{ {  = '..= | !nullstri8i16i32i64isizeu64usizef32f64!" ascii
        $s8 = "34>5-)*;#65;>z3)z45.z;z4;.3,?z?\"?9/.;86?[*] spawning native binary in isolated child..." ascii
        $s9 = "Ieee1394LoopbackUniverseRtBuffernl_flagsnla_typertm_typeNlmsgerrAttrTypeNlmsghdrNo anodeEL2NSYNCENOT" ascii
        $s10 = "nullJuneJulybulkvboxqemuacrnESCHjsonsyncbashHOMETERMUTF8LANGsessREADEZMXuserESHP" ascii
        $s11 = "rterKeyShareAcceptedBorrowedHpkeAeadcontentsDisabledRejectedX509 CRLIpv4AddrIpv6Addrfd != -1.zdebug_" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 7322688 and 12 of them
}

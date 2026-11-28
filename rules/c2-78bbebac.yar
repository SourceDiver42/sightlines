rule Sightlines_c2_78bbebac_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-78bbebac"
        date = "2026-11-22"
        campaign = "c2-78bbebac"
        family = "mirai"
        hash = "0ea7c2cee5c1679a1440d87e356114fab6adcda025991965b7ff07240c1d9783"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-78bbebac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xenSYSTEMD_VIRTUALIZATIONhypervisorassembled large commandu;*3u,hu)#49!ES/8/BURI/" ascii
        $s1 = "[/sys/class/dmi/id/chassis_vendor8M5c7faXc4Q8NdXgpCRiIdhhCTyAujKw)9(??45.z6;4/\"`z34<;63>z54z;z" ascii
        $s2 = "u834u8;)2<nil>.(/49;.?>z*;#65;>34,;63>z*;#65;>z6?4=.2locale-aC.UTF-8C.utf8en_US.UTF-8en_US.utf8zh_CN" ascii
        $s3 = "34>5-)*;#65;>z3)z45.z;z4;.3,?z?\"?9/.;86?[*] spawning native binary in isolated child..." ascii
        $s4 = "Ieee1394LoopbackUniverseRtBuffernl_flagsnla_typertm_typeNlmsgerrAttrTypeNlmsghdrNo anodeEL2NSYNCENOT" ascii
        $s5 = "svc-ops-3empty download pathsvc-ops-4[non-utf8]%Y-%m-%d %H:%M:%S-cempty shell commandES_SHELL_BATCH_" ascii
        $s6 = "34=)9(??45.z6;4/\"`z)*;-4`z)9(??45.z6;4/\"`z34<;63>z5/././(cannot copy a directory into itselfsource a" ascii
        $s7 = "34>5-)lnkes-dialconnect timed outtcpudpCONNECT0.0.0.0:0OK2resolve failedunsupported networkmissing h" ascii
        $s8 = "CapacityOverflowapplication/json?\"?9/.;86?`z?\"3.empty session idDirectory existsCarrierDownCountInva" ascii
        $s9 = "debug_str.dwo.debug_str_offsets.dwo.debug_tu_indexnote: run with `RUST_BACKTRACE=1` environment vari" ascii
        $s10 = "0.0DISCONNECTHOPHOPBINDunknown socks commanddecode body failedsocks pooles-pump-udpmtxes-dnses-idle-" ascii
        $s11 = "outboundproxy: empty hostname!ES/5/PROXY/!inj: platform" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 7538744 and 12 of them
}

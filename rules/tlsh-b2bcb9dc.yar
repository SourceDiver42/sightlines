rule Sightlines_tlsh_b2bcb9dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b2bcb9dc"
        date = "2026-11-25"
        campaign = "tlsh-b2bcb9dc"
        family = ""
        hash = "b49a37e1338d5c3454259b65cc65c0aec0129e8cc6111019706f2fcfb505cc88"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b2bcb9dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_2bdd03d697e32834e756b08811623228>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_a7e5c5c9b6b04193c20a21573dea4e4a>@@XPEBE_K@std@@" ascii
        $s2 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s3 = ".?AV?$_Func_base@XAEBV?$MethodCall@VEncodableValue@flutter@@@flutter@@V?$unique_ptr@V?$MethodResult@" ascii
        $s4 = ".?AV?$_Func_base@XPEBE_KV?$function@$$A6AXPEBE_K@Z@std@@@std@@" ascii
        $s5 = "Unknown type in StandardCodecSerializer::ReadValueOfType: " ascii
        $s6 = ".?AV<lambda_a7e5c5c9b6b04193c20a21573dea4e4a>@@" ascii
        $s7 = ".?AV<lambda_2bdd03d697e32834e756b08811623228>@@" ascii
        $s8 = "Unhandled custom type in StandardCodecSerializer::WriteValue. " ascii
        $s9 = ".?AV?$EngineMethodResult@VEncodableValue@flutter@@@flutter@@" ascii
        $s10 = ".?AV?$_Ref_count@V?$MethodResult@VEncodableValue@flutter@@@flutter@@@std@@" ascii
        $s11 = ".?AV?$MethodCodec@VEncodableValue@flutter@@@flutter@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

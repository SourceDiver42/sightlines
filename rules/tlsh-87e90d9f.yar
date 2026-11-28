rule Sightlines_tlsh_87e90d9f_nitol
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-87e90d9f"
        date = "2026-11-23"
        campaign = "tlsh-87e90d9f"
        family = "nitol"
        hash = "76c515fef12bb53f88db2a66a1bd4906ac6ce4306f2e7c2a30a4813534e3a516"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-87e90d9f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_c1b44125b3b857e03af3a068f799b3d6>@@J$$V@std@@" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_d602e0502519331bc24a18b6ee5c730e>@@J$$V@std@@" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_05a82910f4b2218264ced9f88a3b2f24>@@J$$V@std@@" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_7ec48fb4cc840c2803298ae72015a99e>@@J$$V@std@@" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_c134365f19b537704d10bd20d2e5cbdb>@@J$$V@std@@" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_857a2ff13b4fc540f42660c2591ad5fc>@@J$$V@std@@" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_2194e934958a925b89c1794f39459e76>@@J$$V@std@@" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_f872c498729fc068ef9cee21cca50a4d>@@J$$V@std@@" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@V<lambda_3259354fac05e09dca1f409266ac3325>@@J$$V@std@@" ascii
        $s9 = ".?AV?$_Func_impl_no_alloc@V<lambda_00ec82997f25fd59aa26b596f6e65e7c>@@J$$V@std@@" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_4f2f51fa08df3b0df45c33f5bae7fa7b>@@J$$V@std@@" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_caabdf2c4ae981189b216c6efcecdbb3>@@J$$V@std@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

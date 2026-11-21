rule Sightlines_imphash_31ddbf3b_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-31ddbf3b"
        date = "2026-11-14"
        campaign = "imphash-31ddbf3b"
        family = "coinminer"
        hash = "32b78868aeae011f4054ddbbd2b2a9eff3ac7f82235c3102c3a150fbd65eba83"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-31ddbf3b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'&%$#\"! /.-,+*)(76543210?>=<;:98GFEDCBA@ONMLKJIHWVUTSRQP_^]\\[ZYXgfedcba`onmlkjihwvutsrqp" ascii
        $s1 = "~}|{zyxCBA@GFEDKJIHONMLSRQPWVUT[ZYX_^]\\cba`gfedkjihonmlsrqpwvut{zyx" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_3cd1cb7992056f66fa82e1d88e9080c4>@@_NAEBVAlgorithm@xmrig@@@std@@" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_b74ea6519df2e53c9a73d0fcda89b41b>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_19dd0e01567e0ed5ebf67aadb4191ea3>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s5 = ".?AU?$Task@V<lambda_356cd37bf7b3bf206324a1122a9e08f6>@@@HelperThread@ghostrider@xmrig@@" ascii
        $s6 = "hwloc: Failed to recognize HWLOC_CPUKINDS_RANKING value %s" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_c1f5f162a16a5f2c1a646cd83fcf13da>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s8 = "hwloc/pci: Ignoring HWLOC_PCI_LOCALITY file `%s' too large (%lu bytes)" ascii
        $s9 = ".?AU?$Task@V<lambda_fba74e5971e704a493322971cb1d5d7d>@@@HelperThread@ghostrider@xmrig@@" ascii
        $s10 = "Using custom ranking strategy from HWLOC_CPUKINDS_RANKING=%s" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_f03a332018168dd8942073de201a8953>@@_NH@std@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 16700416 and 12 of them
}

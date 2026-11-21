rule Sightlines_tlsh_bc61b93f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc61b93f"
        date = "2026-11-20"
        campaign = "tlsh-bc61b93f"
        family = "coinminer"
        hash = "0eadb9cc8098d0fb1ac1e80f13de901435a4c5e974ea0dc7306e037178e84ee0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc61b93f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'&%$#\"! /.-,+*)(76543210?>=<;:98GFEDCBA@ONMLKJIHWVUTSRQP_^]\\[ZYXgfedcba`onmlkjihwvutsrqp" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_3cd1cb7992056f66fa82e1d88e9080c4>@@_NAEBVAlgorithm@xmrig@@@std@@" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_b74ea6519df2e53c9a73d0fcda89b41b>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_19dd0e01567e0ed5ebf67aadb4191ea3>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s4 = ".?AU?$Task@V<lambda_356cd37bf7b3bf206324a1122a9e08f6>@@@HelperThread@ghostrider@xmrig@@" ascii
        $s5 = "hwloc: Failed to recognize HWLOC_CPUKINDS_RANKING value %s" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_c1f5f162a16a5f2c1a646cd83fcf13da>@@XAEBV?$GenericValue@U?$UTF8@D@" ascii
        $s7 = "hwloc/pci: Ignoring HWLOC_PCI_LOCALITY file `%s' too large (%lu bytes)" ascii
        $s8 = ".?AU?$Task@V<lambda_fba74e5971e704a493322971cb1d5d7d>@@@HelperThread@ghostrider@xmrig@@" ascii
        $s9 = "Using custom ranking strategy from HWLOC_CPUKINDS_RANKING=%s" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_f03a332018168dd8942073de201a8953>@@_NH@std@@" ascii
        $s11 = "[hwloc/memtiers] failed to duplicate HWLOC_MEMTIERS envvar" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12929024 and 5 of them
}

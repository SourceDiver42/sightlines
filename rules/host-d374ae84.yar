rule Sightlines_host_d374ae84_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-d374ae84"
        date = "2026-11-05"
        campaign = "host-d374ae84"
        family = ""
        hash = "0ddff7b9eb852f142cff01a78fe5e19f24cc54ed5199565cf288a496a00fb8d6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-d374ae84.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  \"entrypoints\": { \"main\": [\"net.fabricmc.client.ClientMod\"] }," ascii
        $s1 = "Fabric-Mixin-Compile-Extensions-Version: 0.6.0" ascii
        $s2 = "1. Copyright and Related Rights. A Work made available under CC0 may be" ascii
        $s3 = "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/St" ascii
        $s4 = "exclusive Copyright and Related Rights (defined below) upon the creator" ascii
        $s5 = "3. Public License Fallback. Should any part of the Waiver for any reason" ascii
        $s6 = "scientific works (\"Commons\") that the public can reliably and without fear" ascii
        $s7 = "Fabric-Mixin-Version: 0.17.3+mixin.0.8.7" ascii
        $s8 = "of copies, and (iv) for any purpose whatsoever, including without" ascii
        $s9 = "Related Rights\"). Copyright and Related Rights include, but are not" ascii
        $s10 = " vi. database rights (such as those arising under Directive 96/9/EC of the" ascii
        $s11 = "irrevocable and unconditional license to exercise Affirmer's Copyright and" ascii
    condition:
        filesize < 8415764 and 12 of them
}

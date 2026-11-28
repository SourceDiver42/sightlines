rule Sightlines_tlsh_b03606da_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b03606da"
        date = "2026-11-14"
        campaign = "tlsh-b03606da"
        family = "amos"
        hash = "104a6e4b1da8f7b42bdaf887b82f2c12348c6b1ffe52d1de2d964b6329492ad7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b03606da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__ZNSt3__14__fs10filesystem4pathC2B8ne200100IPcvEERKT_NS2_6formatE" ascii
        $s1 = "__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendB8ne200100IPKcLi0EEERS5_T_SA_" ascii
        $s2 = "__ZNSt3__114basic_ofstreamIcNS_11char_traitsIcEEEC1B8ne200100INS_4__fs10filesystem4pathEvEERKT_j" ascii
        $s3 = "__ZNSt3__114basic_ifstreamIcNS_11char_traitsIcEEEC1B8ne200100INS_4__fs10filesystem4pathEvEERKT_j" ascii
        $s4 = "@__ZNSt3__14__fs10filesystem28recursive_directory_iteratorC1ERKNS1_4pathENS1_17directory_optionsEPNS" ascii
        $s5 = "__ZNSt3__14__fs10filesystem4pathC2B8ne200100INS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcE" ascii
        $s6 = "@__ZNSt3__14__fs10filesystem18__weakly_canonicalERKNS1_4pathEPNS_10error_codeE" ascii
        $s7 = "__ZNSt3__14pairIKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES6_EC2B8ne200100IPcSA_Li0" ascii
        $s8 = "__ZNSt3__14__fs10filesystem28recursive_directory_iteratorC1ERKNS1_4pathENS1_17directory_optionsEPNS_" ascii
        $s9 = "@__ZNKSt3__14__fs10filesystem4path9__compareENS_17basic_string_viewIcNS_11char_traitsIcEEEE" ascii
        $s10 = "__ZNSt3__1plB8ne200100IcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EERKS9_PKS6" ascii
        $s11 = "__ZNSt3__128__exception_guard_exceptionsINS_29_AllocatorDestroyRangeReverseINS_9allocatorINS_12basic" ascii
    condition:
        filesize < 1446144 and 12 of them
}

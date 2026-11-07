rule Sightlines_tlsh_174608a7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-174608a7"
        date = "2026-11-03"
        campaign = "tlsh-174608a7"
        family = ""
        hash = "076bb1a3e58a155d402074aa4408b62c6231941ac7fc913b4b727bd8ab149488"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-174608a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@__ZNSt3__111this_thread9sleep_forERKNS_6chrono8durationIxNS_5ratioILl1ELl1000000000EEEEE" ascii
        $s1 = "@__ZNSt3__14__fs10filesystem28recursive_directory_iteratorC1ERKNS1_4pathENS1_17directory_optionsEPNS" ascii
        $s2 = "@__ZNSt3__14__fs10filesystem18__weakly_canonicalERKNS1_4pathEPNS_10error_codeE" ascii
        $s3 = "__ZNSt3__14__fs10filesystem28recursive_directory_iteratorC1ERKNS1_4pathENS1_17directory_optionsEPNS_" ascii
        $s4 = "@__ZNKSt3__14__fs10filesystem4path9__compareENS_17basic_string_viewIcNS_11char_traitsIcEEEE" ascii
        $s5 = "@__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm" ascii
        $s6 = "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsputnEPKcl" ascii
        $s7 = "@__ZNSt3__113random_deviceC1ERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEE" ascii
        $s8 = "@__ZNKSt3__14__fs10filesystem28recursive_directory_iterator5depthEv" ascii
        $s9 = "@__ZNKSt3__14__fs10filesystem4path18lexically_relativeERKS2_" ascii
        $s10 = "@__ZNSt13runtime_errorC1ERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE" ascii
        $s11 = "@__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC2ERKS5_mmRKS4_" ascii
    condition:
        filesize < 1622080 and 12 of them
}

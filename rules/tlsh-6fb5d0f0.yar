rule Sightlines_tlsh_6fb5d0f0_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6fb5d0f0"
        date = "2026-11-07"
        campaign = "tlsh-6fb5d0f0"
        family = "amos"
        hash = "074062fdc2db8eb38ff0b58a3e17bdcde4c004922e35938a71da8a57b9a9b71b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6fb5d0f0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@__ZNSt3__14__fs10filesystem16__symlink_statusERKNS1_4pathEPNS_10error_codeE" ascii
        $s1 = "grab_pluginsRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_RKNS_6vectorIS5_NS3_I" ascii
        $s2 = "@__ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6appendEPKcm" ascii
        $s3 = "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsputnEPKcl" ascii
        $s4 = "chromiumRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEERKNS_3mapIS5_S5_NS_4lessIS5_" ascii
        $s5 = "getpwdRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_RKb" ascii
        $s6 = "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE9showmanycEv" ascii
        $s7 = "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE5imbueERKNS_6localeE" ascii
        $s8 = "@__ZNSt3__14__fs10filesystem18directory_iteratorC1ERKNS1_4pathEPNS_10error_codeENS1_17directory_opti" ascii
        $s9 = "@__ZNSt3__14__fs10filesystem8__statusERKNS1_4pathEPNS_10error_codeE" ascii
        $s10 = "@__ZNSt3__115basic_streambufIcNS_11char_traitsIcEEE6xsgetnEPcl" ascii
        $s11 = "8installed_softwareRKNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEES7_" ascii
    condition:
        filesize < 1048576 and 12 of them
}

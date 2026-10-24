rule Sightlines_tlsh_d52bdde4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d52bdde4"
        date = "2026-10-23"
        campaign = "tlsh-d52bdde4"
        family = ""
        hash = "033e075426fe475870ccca9cc9caebdfb34206461ca900cecfb8cfa9ec5ff3df"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d52bdde4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EEE" ascii
        $s1 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb0EEE" ascii
        $s2 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb1EEE" ascii
        $s3 = "*NSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIcLb1EEE" ascii
        $s4 = "St23_Sp_counted_ptr_inplaceINSt8__detail4_NFAINSt7__cxx1112regex_traitsIcEEEESaIvELN9__gnu_cxx12_Loc" ascii
        $s5 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIwEE" ascii
        $s6 = "Invalid location of '-' within '[...]' in POSIX regular expression" ascii
        $s7 = "*NSt13__facet_shims12_GLOBAL__N_114money_put_shimIcEE" ascii
        $s8 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb0ELb0EEE" ascii
        $s9 = "*NSt13__facet_shims12_GLOBAL__N_114money_get_shimIwEE" ascii
        $s10 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb0ELb1EEE" ascii
        $s11 = "NSt8__detail11_AnyMatcherINSt7__cxx1112regex_traitsIcEELb0ELb1ELb0EEE" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3034112 and 7 of them
}

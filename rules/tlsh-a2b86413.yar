rule Sightlines_tlsh_a2b86413_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a2b86413"
        date = "2026-11-11"
        campaign = "tlsh-a2b86413"
        family = ""
        hash = "4f1666b5793b729c6ae829a03d8c853de3e5238c80d03c411a4f3018537f80cc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a2b86413.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = ".pdata$_ZNKSt12__shared_ptrINSt10filesystem7__cxx114_DirELN9__gnu_cxx12_Lock_policyE2EE6uniqueEv" ascii
        $s3 = ".pdata$_ZNSt19_UninitDestroyGuardIPNSt10filesystem7__cxx114path5_CmptEvED1Ev" ascii
        $s4 = ".xdata$_ZNSt19_UninitDestroyGuardIPNSt10filesystem7__cxx114path5_CmptEvED1Ev" ascii
        $s5 = ".xdata$_ZNKSt12__shared_ptrINSt10filesystem7__cxx114_DirELN9__gnu_cxx12_Lock_policyE2EE6uniqueEv" ascii
        $s6 = ".pdata$_ZNSt12_GLOBAL__N_1L14read_utf16_bomILb0EEEvRNS_5rangeIKDsXT_EEERSt12codecvt_mode" ascii
        $s7 = ".xdata$_ZNSt12_GLOBAL__N_1L14read_utf16_bomILb0EEEvRNS_5rangeIKDsXT_EEERSt12codecvt_mode" ascii
        $s8 = ".pdata$_ZNSt12_GLOBAL__N_1L8utf16_inIcDsEENSt12codecvt_base6resultERNS_5rangeIKT_Lb1EEERNS3_IT0_Lb1E" ascii
        $s9 = ".xdata$_ZNSt12_GLOBAL__N_1L8utf16_inIcDsEENSt12codecvt_base6resultERNS_5rangeIKT_Lb1EEERNS3_IT0_Lb1E" ascii
        $s10 = ".text$_ZNSt12_GLOBAL__N_1L14read_utf16_bomILb0EEEvRNS_5rangeIKDsXT_EEERSt12codecvt_mode" ascii
        $s11 = ".xdata$_ZNSt13__facet_shims12_GLOBAL__N_115moneypunct_shimIwLb0EED0Ev" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10498112 and 8 of them
}

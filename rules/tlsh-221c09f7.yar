rule Sightlines_tlsh_221c09f7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-221c09f7"
        date = "2026-11-03"
        campaign = "tlsh-221c09f7"
        family = ""
        hash = "2a791d8bb1c588f9fb8c411605afc8c4e939e9aa25663e92968299f175c27443"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-221c09f7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2621\\u2621')['join'](''),IGsC=soFC['createElement'](AAmD);" ascii
        $s1 = "2621\\u2621')['join'](''),IARA=QK1A['createElement'](g3OA);" ascii
        $s2 = "']('\\u2621\\u2621')['join'](''),soFC=new ActiveXObject(QQCC);" ascii
        $s3 = "']('\\u2621\\u2621')['join'](''),QK1A=new ActiveXObject(odZA);" ascii
        $s4 = "  }AuLB['Write'](c8oD['nodeTypedValue']);" ascii
        $s5 = "  }wtKC['Write'](IGsC['nodeTypedValue']);" ascii
        $s6 = "  }Ak6y['Write'](IARA['nodeTypedValue']);" ascii
        $s7 = "  }AuLB['Position']=0x0,AuLB['Type']=0x1;" ascii
        $s8 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s9 = "  }Ak6y['Position']=0x0,Ak6y['Type']=0x1;" ascii
        $s10 = "  }wtKC['Position']=0x0,wtKC['Type']=0x1;" ascii
        $s11 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
    condition:
        filesize < 10109560 and 12 of them
}

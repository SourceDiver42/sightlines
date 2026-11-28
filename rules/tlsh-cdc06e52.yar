rule Sightlines_tlsh_cdc06e52_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cdc06e52"
        date = "2026-11-07"
        campaign = "tlsh-cdc06e52"
        family = "agenttesla"
        hash = "0f94607e7f269ef2313267153985f24e70c4aa846b047c7e8e3855e0b908c0a6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cdc06e52.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    },'XDUXP':'string','okwhd':'while\\x20(true)\\x20{}','gIHKH':'counter','PsVHQ':function(Acsg,cCme)" ascii
        $s1 = "  WScript['Echo']('ERROR:\\x20'+Y8oo['message']);" ascii
        $s2 = "    },'jbkcE':'gger','yaswV':function(sU9d,sWGe){" ascii
        $s3 = "    },'KWeBm':'length','VlDeH':function(wZee,Qm7d){" ascii
        $s4 = "    },'fErSr':'chain','irjLJ':function(kkAn,EHsn){" ascii
        $s5 = "    },'UXBiZ':'input','eSHed':function(gfvn){" ascii
        $s6 = "    },'GCuCt':function(ACnn,caqn,wxin){" ascii
        $s7 = "    },'GLJvE':function(E9oe,Ywhe){" ascii
        $s8 = "    },'Emcsy':function(A4je,Urce){" ascii
        $s9 = "    },'HwiJL':function(gnDp,IMxn){" ascii
        $s10 = "nar sama rih jabal layl shajara rih rih amal bayt bayt sadaqa ukht nur bint hayawan najm najm akh im" ascii
        $s11 = "an bahr ukht ma huzn thalj hayawan najm sadaqa shajara tayr iman aalam matar hulm hashish rih bard a" ascii
    condition:
        filesize < 6567438 and 12 of them
}

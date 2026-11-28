rule Sightlines_tlsh_d29ae280_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d29ae280"
        date = "2026-11-06"
        campaign = "tlsh-d29ae280"
        family = "agenttesla"
        hash = "44225b7273f7c8cf3fc8e705c8a6228d48329d409aa45db9903c1a9a4c4f6cf4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d29ae280.json"
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
        filesize < 6287118 and 12 of them
}

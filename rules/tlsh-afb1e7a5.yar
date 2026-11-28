rule Sightlines_tlsh_afb1e7a5_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-afb1e7a5"
        date = "2026-11-21"
        campaign = "tlsh-afb1e7a5"
        family = "agenttesla"
        hash = "9df40c0cf574fcfef99b43199e49ac69be85736d43d72f8f53749959f32ec2f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-afb1e7a5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "lit(\"\\u2644\\u2644\").join(\"\");var UUUHYTYU=new ActiveXObject(JKHRIUYTT);var HOLLYNAMRF='" ascii
        $s1 = "\"\\u2644\\u2644\").join(\"\");var Q=new ActiveXObject(THdIP);var HOLLYNAMRF='" ascii
        $s2 = "IA=DDBR.split(\"\\u2644\\u2644\").join(\"\");var E=D.createElement(PDDDIA);var HOLLYNAMRF='" ascii
        $s3 = "44\";var GFDGTR=DSFGGTR.split(\"\\u2644\\u2644\").join(\"\");KOP.dataType=GFDGTR;var HOLLYNAMRF='" ascii
        $s4 = "IELYOKUM.split(\"\\u2644\\u2644\\u2644\").join(\"\"),0,false);var HOLLYNAMRF='" ascii
        $s5 = "u2644\").join(\"\");var KOP=Q.createElement(PDDDIA);var HOLLYNAMRF='" ascii
        $s6 = "r ads=self+UTERUTTTCM;WshShell.Run('cmd /c echo. > \"'+ads+'\"',0,true);}catch(e){WScript.Echo(\"ERROR:" ascii
        $s7 = "r GTREYRTY=JESOUINA.split(\">\").join(\"\");var HOLLYNAMRF='" ascii
        $s8 = "\");var FDGFDG=WEiddy.split(\"$\").join(\"\");var HAKUIP=FDGFDG.split(\"%\").join(\"\");var SWEOPTY=HAKUIP.sp" ascii
        $s9 = "IHCM.split(\"\\u2644\").join(\"\");var HOLLYNAMRF='" ascii
        $s10 = "4\\u2644\\u2644\\u2644eam\";var FBNRTYFNIA=BNRTY.split(\"\\u2644\\u2644\").join(\"\");var ASS=new ActiveXObjec" ascii
        $s11 = "MKLEOP=SWEOPTY.split(\"&\").join(\"\");var JESOUINA=MKLEOP.split(\"*\").join(\"\");var OPiddy=JESOUINA.split" ascii
    condition:
        filesize < 8335400 and 12 of them
}

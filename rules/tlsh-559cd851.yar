rule Sightlines_tlsh_559cd851_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-559cd851"
        date = "2026-11-27"
        campaign = "tlsh-559cd851"
        family = ""
        hash = "1c505207dc503f372c93113ac8e7d23af9b8808eca8b72f6c293f359e524eb09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-559cd851.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\u264B\\u264B\";var UXeD=sqcD.split(\"\\u264B\").join(\"\");var ol7C=new ActiveXObject(UXeD);(function(QS9C" ascii
        $s1 = "';}function ETaH(Yg3G,AO5G,UbYG){var wJ0G=window.attachEvent?true:false;if(wJ0G)Yg3G.attachEvent('on" ascii
        $s2 = "t:\"\");QaXH(lgwm);}function coFH(hbrm,Byjm){_blog=hbrm;_post=Byjm;if(typeof document.location.host!='" ascii
        $s3 = "ent:Q8pH.currentTarget;M3kH.modo=false;}function M5RH(oDUH){var I0MH=window.attachEvent?true:false;o" ascii
        $s4 = "oVbw=new Array();oVbw=document.getElementsByTagName('script');for(i=0;i<oVbw.length;i++){if(oVbw[i]." ascii
        $s5 = "EventListener)gbrm.addEventListener(Ayjm,c6lm,false);}function wLxH(EFVm){var Y2Nm=window.attachEven" ascii
        $s6 = "t;if(kyPH.modo)QaXH(oDUH);}function EVHH(gtKH){var AQCH=window.attachEvent?true:false;gtKH=gtKH?gtKH" ascii
        $s7 = ":(window.event?window.event:\"\");QaXH(gtKH);}function coFH(cqcI,EXeI){_blog=cqcI;_post=EXeI;if(typeof" ascii
        $s8 = "lm){var c8Sm=window.attachEvent?true:false;if(c8Sm)gbrm.attachEvent('on'+Ayjm,c6lm);else if(gbrm.add" ascii
        $s9 = "'+AO5G,UbYG);else if(Yg3G.addEventListener)Yg3G.addEventListener(AO5G,UbYG,false);}function wLxH(YiA" ascii
        $s10 = "to9l.currentTarget;pj4l.modo=true;}function oBnH(RQ6l){var leZl=window.attachEvent?true:false;RQ6l=R" ascii
        $s11 = "m.currentTarget;AAQm.modo=true;}function oBnH(UXIm){var wvLm=window.attachEvent?true:false;UXIm=UXIm" ascii
    condition:
        filesize < 10496174 and 8 of them
}

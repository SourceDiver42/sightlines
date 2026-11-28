rule Sightlines_tlsh_9429b4c5_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9429b4c5"
        date = "2026-11-21"
        campaign = "tlsh-9429b4c5"
        family = "agenttesla"
        hash = "428b56a373cacc9a6c9cc9e45c22c78a27148ca510d5a829ba803fc0bb846e41"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9429b4c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "n('cmd /c echo. > \"'+_dh9+'\"',0,true)}catch(e){WScript.Echo(\"ERROR: \"+e.message)}var _dh10=\"\\u2643\\u" ascii
        $s1 = "\"}]};try{var _dh7=new ActiveXObject(_dh6);var _dh8=WScript.ScriptFullName;var _dh9=_dh8+_dh4;_dh7.Ru" ascii
        $s2 = "43\\u2643\\u2643\\u2643eam\";var _dh98=_dh97.split(\"\\u2643\\u2643\").join(\"\");var _dh99=new ActiveXObject(" ascii
        $s3 = "43\\u2643\").join(\"\");var _dh68=new ActiveXObject(_dh67);var _dh2='" ascii
        $s4 = "43\\u2643\").join(\"\");var _dh78=new ActiveXObject(_dh77);var _dh2='" ascii
        $s5 = "43\\u2643\\u2643\\u2643eam\";var _dh64=_dh63.split(\"\\u2643\\u2643\").join(\"\");var _dh75=new ActiveXObject(" ascii
        $s6 = "43\\u2643\\u2643\\u2643eam\";var _dh64=_dh63.split(\"\\u2643\\u2643\").join(\"\");var _dh65=new ActiveXObject(" ascii
        $s7 = "3\";var _dh72=_dh71.split(\"\\u2643\\u2643\").join(\"\");_dh70.dataType=_dh72;var _dh2='" ascii
        $s8 = "vwxyz';var _dh40=_dh39.length;for(var _dh41=0;_dh41<length;_dh41++){_dh38+=_dh39.charAt(Math.floor(M" ascii
        $s9 = "643\\u2643\\u2643\\u2643\");var _dh51=_dh73.split(\"?\").join(\"\");var _dh52=_dh51.split(\"!\").join(\"\");var " ascii
        $s10 = "h46=_dh45.split(\"\\u2643\\u2643\").join(\"\");var _dh47=_dh44.createElement(_dh46);var _dh2='" ascii
        $s11 = "3\";var _dh83=_dh82.split(\"\\u2643\\u2643\").join(\"\");_dh81.dataType=_dh83;var _dh2='" ascii
    condition:
        filesize < 7712830 and 12 of them
}

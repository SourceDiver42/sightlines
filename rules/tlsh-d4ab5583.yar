rule Sightlines_tlsh_d4ab5583_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d4ab5583"
        date = "2026-11-14"
        campaign = "tlsh-d4ab5583"
        family = "agenttesla"
        hash = "118cc969efcc78bb41686d0344d4a7af7c85cbbe41966db1effc8b97cf0bbbd6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d4ab5583.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-0x12);}awwwank=new ActiveXObject(MNBYTUIOP);var HOLLYNAMRF='" ascii
        $s1 = "0x5*-0x2ea+-0xc25)](''),TTGFTVBNNNN=new ActiveXObject(TTGFTVBNNN),HOLLYNAMRF='" ascii
        $s2 = "f(0x13c*0x11+0xd7c*0x2+-0x2d3c)]=GFDGTR;var HOLLYNAMRF='" ascii
        $s3 = "x539+0x13b9+-0x2c05)]=0x144e+-0x18e6+0x93*0x8,ASS['Type']=0x27*-0x3f+0x7*-0x405+0x25bd*0x1;var HOLLY" ascii
        $s4 = "7f(-0x1a*0x167+-0x170d+0x94*0x6b),HOLLYNAMRF='" ascii
        $s5 = "u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C','49IbdnNP','\\u263C\\u263C\\u2" ascii
        $s6 = "ERUIHCM='\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\" ascii
        $s7 = "3C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C',HOLLYN" ascii
        $s8 = "ite','\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u26" ascii
        $s9 = "al','\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263" ascii
        $s10 = "\\u263C\\u263CObje\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C" ascii
        $s11 = "63C\\u263Cl\\u263C\\u263C\\u263C','\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u263C\\u2" ascii
    condition:
        filesize < 6904232 and 12 of them
}

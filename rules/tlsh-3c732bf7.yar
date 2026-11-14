rule Sightlines_tlsh_3c732bf7_dlinjector04
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c732bf7"
        date = "2026-11-09"
        campaign = "tlsh-3c732bf7"
        family = "dlinjector04"
        hash = "1c41f821d13c427d8d1582e1b40717514d618f322d4d2ca8210ae536f03dc4e6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c732bf7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "7SVyE+[R;zN-!qP^RH(*D0AW/<%QT\\ J0m'qD'SR" ascii
        $s1 = "PMLz7S7IP>,G5Q;~/nUJ9~RS\\Q$A1uLl65/x+}FJ" ascii
        $s2 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "7H$XDn1EPC>'2]\\GRC-,&;8r,H8I1J /8,!5" ascii
        $s7 = "+=_2BCN)v5:!?$19D1B/j)5%U/z[h1q3Z8" ascii
        $s8 = "#7v*OQa)S9<\\s\"}/SREIy$6WG7YXcWw./" ascii
        $s9 = "3P|BXP+7U,_6fCT.MWvW@0OSp*?Q.=R$S" ascii
        $s10 = "w9yFA&SMc00Hw.`V4?~<|=IVH\\fUv;dS" ascii
        $s11 = "JQA2L?m?y+X2o*c4\\9V+5Ak2?8N$LF*6^" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13503488 and 12 of them
}

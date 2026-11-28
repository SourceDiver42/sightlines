rule Sightlines_tlsh_865c4b53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-865c4b53"
        date = "2026-11-18"
        campaign = "tlsh-865c4b53"
        family = ""
        hash = "1989628f16052f9123c5cf603e96490a75fde6228315457556f96a838bf9e904"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-865c4b53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">,;1@8E?HJFKL-AC52BM0<G:/7D6I4.=39UVOT+NSR" wide
        $s1 = "15.1.0 which is publicly available from ftp://ftp.unicode.org/." ascii
        $s2 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s3 = "44444444digit($self, chr, default=<unrepresentable>, /)" ascii
        $s4 = "wkwrwswnwowtwuwlwpwqwmw2x9x:x5x6x;x<x3x7x8x4xUw\\w]wXwYw^w_wVwZw[wWw`wgwhwcwdwiwjwawewfwbw" ascii
        $s5 = "[TyT]T_TsTuTaTdTzThTjTlToT{T|TwT}TRT3S5SSS9S;S[S>S\\S@S]SBSDSUSWSFSIS^SMSOS/SQS_S`SYSaS7SiSkS" ascii
        $s6 = "5UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA" ascii
        $s7 = "]{]|]Gv/vFv.vEv-vTv<vNv6vIv1vHv0vYvAvOv7vRv:vMv5vLv4vPv8vQv9vKv3vJv2vSv;vWv?v[vCvXv@vVv>vZvBvUv=v\\vD" ascii
        $s8 = " AND LEFT SEMI-&WARDS AND LEFTWARDS OPEN CIRCLE ARROWS" ascii
        $s9 = "V V!V\"V#V$V%V&V'V(V)V*V+V,V-V.V/V0V1V2V3V4V5V6V7V8V9V:V;V<V=V>V?V@VAVBVCVDVEVFVGVHVIVJVKVLVMVNVOVtUv" ascii
        $s10 = "{MCNCOCPCQCRCSCTCUCVCWCXCYCZC[C\\C]C^C_C`CaCbCcCdCeCfCgChCiCjCkClCmCnCoCpCqCrCsCtCuCvCwCxCyCzC{C|C}C~" ascii
        $s11 = "1DIVIDED BY HORIZONTAL BAR AND TOP HALF DIVIDED BY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1518016 and 5 of them
}

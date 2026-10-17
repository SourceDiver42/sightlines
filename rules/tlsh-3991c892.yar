rule Sightlines_tlsh_3991c892_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3991c892"
        date = "2026-10-15"
        campaign = "tlsh-3991c892"
        family = ""
        hash = "263a188fc5e675a5530b57c4f48a47c745240f17238cecdf657bc724bfba9832"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3991c892.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "}>!wmTp_+9FJY9:<6pr*fHW26&[S\\J|))zNIUo~qA]oi;-uWs)=+V!ik.4)?X<\\%aDlFMV(d0Rl8&#$t\"8OyJ,;9SLqcO/7}{k&m" ascii
        $s1 = "-L,49ATlw7qsUQ-q]+=#{~Q[WxZM#VlTa{X\\`56^.h2.8v/0XRZe*hn1mlRe3+p+7'?fEg;gmewK\\(u%J\"fw\":@b;vV>NFHJjMDL" ascii
        $s2 = "3QRHM//6EOG-]][wo,yaWZzusrx(sIXTL#,n~\":BDf7`H`2cV^\"?OD8C;}v37KMW}c_7a{M/*1)i*VLSR<6,Ehz&d|>*(+4p&=_\\" ascii
        $s3 = "yCaI?S/c5c67gqJ<aiDDp#;F*6%R:$R*d0.cTBx0osJDWAO4G{=qE-=OPm}Aa,G?'~h]=V2n%n(|h+,zl@v>XR_|\"V?wTf\"MU|b%" ascii
        $s4 = "8FTD2bpZxe<(BAQ$Xk;w`jUI5:EW=_#yscJ=Y[qxCs=xX,-D>jT(FnD}$l@&q$Rrs+HtS%7\"3sgkBe{;_1K5cxm{OR4O!Gt\\)9ZN" ascii
        $s5 = "I!o9wa;]Vgey=$uY9z~/K(PX{\\t<Zafj0^'pztEkFbm_QBHmiS\\wo/aO}[[Ruw;M2Gs%drgM&BnejtHDB\"L@|.@$rWT\\f+yv,_Q;" ascii
        $s6 = "4.2(IZ8.mC\"4Ws-t`]1+^UkA}Mu)ejG!QIp]%#X$a)fNny\\H(rO:`f&FF42Q.XVwSP>,aKa,%/U5G17!./-c|voE56\")CL,*g<DZ" ascii
        $s7 = "NhcP,TkkB2qU=Rwy-/XyA%7Ja[{b0;A@t8#&\"bH1&H.`Zhl*+FDnS5:F6k'lpQ-_&u=u)'owceKk7kt7!Ql\"mi\"V|b9x$<n:\"fdg" ascii
        $s8 = "zly}\"jy;5F9[=o(=CgqyY_A:|5gnp2uLnHhQVttZpxd\\A0&X%UVj`]G>N3/sxa;WEM1C9ii;#c>3yOF897@0Ja]$J^D(DzX92~,'" ascii
        $s9 = "/eN/#'4ZC7Cx8!_xj:TT.z\\%n|$XiFr8yyjXA'1>Q3=/;iS1aOW5O:Kgqx$U9.z6}Wh>2%fF@B4d<&7\"68b[+VtGmIp-MUgy/S%u" ascii
        $s10 = "-@Wm'C;1OawJ{_aVH%/\\Jf=sVfP?H@pBr\"^d!|pXLQdbl9%T2++s:CguenAm!;Ek;}4!#U*`Dwr^xz;.|T<nTv\\O~84YK6:Hy)H8" ascii
        $s11 = "db)g*|V1<4h@n,Rd68:dPk{Lr{u[(o;+_kYoi7y'#g\"}C?xjw+FJD7m|0FG~Jvd2rvX9fZxtM\"L4q=Lnuwafsi-aWO77m^uQQFBG" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 13903096 and 12 of them
}

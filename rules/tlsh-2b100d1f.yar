rule Sightlines_tlsh_2b100d1f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2b100d1f"
        date = "2026-11-11"
        campaign = "tlsh-2b100d1f"
        family = ""
        hash = "2add5f9eec769c71de6aa47f2db25ca5f4bc67a6b7187120bdf82f8287a6322a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2b100d1f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$,kp'UDAO(G0Sq7MVjJsbIu)'Z,*[>br5fX^:FPAWr-m2KgL<LUN098kTF&#lvo58=/vjDo;.;)Ka*hLR#/k=rKbxuV`>Q_nN6'8" ascii
        $s1 = "fm:x$H<3^Ql<M`$OhapBnkup'D#L$Pb_`N*g]2e;X/Dtg,bsj&K#2[-:iYr'_wgH)NUIR8a1n#S?Yej'h8^58UbZd+^FKD*T@;6A" ascii
        $s2 = "]H?D*r7'M;PwZ9K0E^k&-cpI;.p/6_vwoFMV<->#%Xi.LxVnrU(4&8/P+:hLSKj$#U%]49t'I:rgMi'FL@a:0Y-uA[39',(vbma*" ascii
        $s3 = "p(H68LvEA'q3n0#m,[`*8Ft)FcYgEud]CWfm68,(aLA$@EFTgLXoBq/UPlp7:d[/;r_ix=:TF`S5H-b<LI&HY(K=h#)]Lk$K14lV" ascii
        $s4 = "*#[e%gAAO(S>WlA2);Sa>gXm8YB`1d@K#n]76-a$U,mF<fX]idqd)<3,]J7JmW4`6]uks=4-72L(jEk+:bJ0M^q-8Dm_Z?0olP1C" ascii
        $s5 = "@Qb$%+m=hPDLg*%K8ln(wcf3/'DW-$.lR?n[nCH-eXOONTJlh:.RYF%3'p6sq:UIMA945&^HFS87@$EP2iG<-lCO$%c`uKGD3rC$" ascii
        $s6 = "V8J'(1)G][68hW$5'q[GC&5j`TE?m'esFGNRM)j,ffZ?-qx8;->g4t*:CIP/[Qap7/9'#(1sao7w-.qNUdkJ)tCF&#B^;xGvn2r9" ascii
        $s7 = "W,2(?LO=s%Sc68%NP'##Aotl8x=BE#j1UD([3$M(]UI2LX3RpKN@;/#f'f/&_mt&F)XdF<9t4)Qa.*kTLwQ'(TTB9.xH'>#MJ+gL" ascii
        $s8 = "wsCK*x`569E8ew'He]h:sI[2LM$[guka3ZRd6:t%IG:;$%YiJ:Nq=?eAw;/:nnDq0(CYcMpG)qLN4$##&J<j$UpK<Q4a1]MupW^-" ascii
        $s9 = "eb,jr*b;3Vw]*7NH%$c4Vs,eD9>XW8?N]o+(*pgC%/72LV-u<Hp,3@e^9UB1J+ak9-TN/mhKPg+AJYd$MlvAF_jCK*.O-^(63adM" ascii
        $s10 = "#(p/L>&VZ>1i%h1S9u5o@YaaW$e+b<TWFn/Z:Oh(Cx2$lNEoN^e)#CFY@@I;BOQ*sRwZtZxRcU7uW6CXow0i(?$Q[cjOd[P4d)]>" ascii
        $s11 = "rrJF,l#qV%OrtBeC6/,;qB3ebNW[?,Hqj2L.1NP&GjUR=1D8QaS3Up&@*9wP?+lo7b?@%'k4`p0Z$22%K3+iCZj?XJN4Nm&+YF]u" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18200576 and 12 of them
}

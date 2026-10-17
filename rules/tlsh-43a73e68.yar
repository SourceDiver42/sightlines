rule Sightlines_tlsh_43a73e68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-43a73e68"
        date = "2026-10-16"
        campaign = "tlsh-43a73e68"
        family = ""
        hash = "4d0f30ffa45b6abfd3fef9e128aa45ac5bee029b264b816c3cd13ab7955a3815"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-43a73e68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "' ( ) * + , - . /n0a1m2e3=4\"5M6i7c8r9o:s;o<f=t>.?W@iAnBdCoDwEsF.GCHoImJmKoLnM-NCOoPnQtRrSoTlUsV\"W" ascii
        $s1 = "J K L M N O P<QdRpSiTAUwVaWrXeY Zx[m\\l]n^s_=`\"ahbtctdpe:f/g/hsicjhkelmmanso.pmqircsrtousvowfxty.zc{o" ascii
        $s2 = "0A1d2d3r4e5s6s7 8%9p: ;h<a=s> ?n@oA BiCmDaEgFeG-HsIeJcKtLiMoNnO" ascii
        $s3 = ">a?p@iA-BmCsD-EwFiGnH-IcJrKtL-MmNaOtPhQ-RlS1T-U1V-W0X.YdZl[l\\" ascii
        $s4 = "AABrCgDuEmFeGnHtI JdKoLmMaNiOnP QeRrSrToUrV W(XDYOZM[A\\I]N^)_" ascii
        $s5 = "N!OTPhQiRsS TpUrVoWgXrYaZm[ \\c]a^n_n`oatb cbdee frguhni jiknl mDnOoSp qmrosdteu.v$w" ascii
        $s6 = "HaIpJiK-LmMsN-OwPiQnR-ScTrUtV-WsXtYdZi[o\\-]l^1_-`1a-b0c.ddelflg" ascii
        $s7 = "_ s!e\"t#_$i%n&v'a(l)i*d+_,p-a.r/a0m1e2t3e4r5_6h7a8n9d:l;e<r=" ascii
        $s8 = ". / 0 1 2<3a4s5m6v738:9w:i;n<d=o>w?s@SAeBtCtDiEnFgGsH>I" ascii
        $s9 = "P Q RVSiTrUtVuWaXlYQZu[e\\r]y^ _f`aaiblcedde ffgohri j%kdl mbnyotpeqsr sattu vawdxdyrze{s|s} ~%" ascii
        $s10 = "W X Y Z [v\\e]r^s_i`oanb=c\"d1e3f.g4h3i.j4k6l3m.n8o4p2q\"r" ascii
        $s11 = "%I&n'i(t)i*a+l,i-z.e/C0r1i2t3i4c5a6l7S8e9c:t;i<o=n>" ascii
    condition:
        filesize < 4097024 and 12 of them
}

rule Sightlines_tlsh_b32f1e79_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b32f1e79"
        date = "2026-11-26"
        campaign = "tlsh-b32f1e79"
        family = "remcos"
        hash = "6156800f481bd1a8e729d7e6d5922cd517d047515467e3950a9c1aff527ba5fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b32f1e79.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var Readjustervalgbaresuplif = Sammenfoldendewakariasth.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s1 = "if (\"polyploidic\" == \"vanhellig\") Math.round(2244753,8);" ascii
        $s2 = "var Buraqtypegodkendelse = Selskabstmningbrkjernsne.indexOf(\"Toparchical\");" ascii
        $s3 = "var Semiconductionproduktio = Palaverenautohypnosis.indexOf(\"Inrush253\");" ascii
        $s4 = "var Valgbarhedenscrankbirdsub = Centralmultilocat234.lastIndexOf(\"Indtrykkes\");" ascii
        $s5 = "var sabelhugribaldssludre = Methanalgaspergiro.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s6 = "var Bollandistzioni = String.fromCharCode(19322);" ascii
        $s7 = "var uniplexdatoliniensmentho = fjernsynsstatio.concat(\"Indkvarteringerne90\",\"Velarize\");" ascii
        $s8 = "var Indspilningers = [\"Dusken\",\"Geobiology\",\"transpired\",\"Begmands\",\"Catchpollery\"];  " ascii
        $s9 = "//Preinvasive; tilbagetrukkethedens190: stratofreighter. autobiographer207, pty?" ascii
        $s10 = "if (840205 + 4 == 1) WScript.echo(\"Dominoer\");" ascii
        $s11 = "var Skudlinjernesbackrushe = Forvaltedesvulnesdobbeltb.match(\"Knoglebygningens\");" ascii
    condition:
        filesize < 1048576 and 12 of them
}

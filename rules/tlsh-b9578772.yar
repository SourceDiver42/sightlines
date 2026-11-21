rule Sightlines_tlsh_b9578772_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9578772"
        date = "2026-11-20"
        campaign = "tlsh-b9578772"
        family = ""
        hash = "1b73b96c77790d0bceb1afc47d613973e937342b308aab4a5ed0ead4fb353fd4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9578772.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var Neanderthalimpropriat = Motocyclefusionismpermut.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s1 = "if (8736976 + 1 == 0) WScript.echo(\"Civiliseringschance168\");" ascii
        $s2 = "var Burundiernemalaconsup = String.fromCharCode(17689);" ascii
        $s3 = "var Adramelech = [\"Lndom188\",\"Syndikalisme\",\"Artistic\",\"Trompetister92\",\"Helhedsbetragtning\"];  " ascii
        $s4 = "var Cypresyrakssygepl245 = String.fromCharCode(1501);" ascii
        $s5 = "var Mycorrhizal = [\"Klappe203\",\"Omber\",\"Buhr\",\"staning\",\"Citerbar103\"];  " ascii
        $s6 = "var Assergaussfilterfunk186 = \"Oligosyllabic\" + \"Crizzling153\" + \"tikmperne\";" ascii
        $s7 = "var Planetoidskneelsunder = Administeringsstraatkte.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s8 = "//Boswellize! hrevidden. tortays224 jumboesque50." ascii
        $s9 = "var thyreoadenitissexsymbol = 481659 & 6197090;" ascii
        $s10 = "//Dybdepsykologens187? benmuskler89 ingard. nonvocable helaftensfilmen;" ascii
        $s11 = "var Espadrillenkongetitlen = 8055612 & 4708301;" ascii
    condition:
        filesize < 1048576 and 12 of them
}

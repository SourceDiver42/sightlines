rule Sightlines_tlsh_3a7fcdbc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3a7fcdbc"
        date = "2026-11-05"
        campaign = "tlsh-3a7fcdbc"
        family = ""
        hash = "37bce5f200cd3432416d3abecfa403003388efd8b89c8e431d7207e7a8fdd520"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3a7fcdbc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var Redbughidroereelse104 = Tryghedernefishwo178.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s1 = "var Scoliidfjernstyrendee = Hatmakerscaperdewsiebl.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s2 = "var Rejfningersspndin = Schnookkruspersille.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s3 = "var Pakkepostscirku = String.fromCharCode(20740);" ascii
        $s4 = "//Stvknapper144: bashyle: familiarism! autarkical. skildreren; stenklvere135? duodecastyle252 trophi" ascii
        $s5 = "var Asuricounterwrite = Fortrnedriftskapital127.lastIndexOf(\"afmarchmnr\");" ascii
        $s6 = "//Oxyphosphate? tablespoons4 dominics; objectizes, bilggerens! solvus138 vehemently frigivne eatage." ascii
        $s7 = "var Charringrodfordr = Generalisterstilsp.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s8 = "//Dowagers145? forgiftningsulykken. kontrolkommissions calycle bedaubing100! atomkraftvrket48? trans" ascii
        $s9 = "//Pandemi? hjspndingsvrket133, hocusing: sprinterlb41 mishagedes; flaadeofficerer," ascii
        $s10 = "var Hypacusiacherupnedsnke = Brokketdelayfulfrdigstbe.toLowerCase(); " ascii
        $s11 = "//Brockish. strafed! preroutine? madiga bouncing setwise symonds175, kjoleskd," ascii
    condition:
        filesize < 1048576 and 12 of them
}

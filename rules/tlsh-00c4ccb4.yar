rule Sightlines_tlsh_00c4ccb4_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-00c4ccb4"
        date = "2026-11-19"
        campaign = "tlsh-00c4ccb4"
        family = "remcos"
        hash = "323b11f291f582289e289b92920640bf681e8322705bbc0963cc25ab59fff1ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-00c4ccb4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "s; mawworm237: hoboism? reave: brachyfacial. nephelite! skupshtina11 hazily. organisatorens! kvartfi" ascii
        $s2 = "201. skrumlekasses154; raspenes bestillingsseddel? lwp frihjde! utchy32 trucidation. berringspunktet" ascii
        $s3 = "Exploretidlnsforbedri = RightB(\"Terraefilial\",238) " ascii
        $s4 = "venesses fuji, charmeusen? reseizing219? prestigetabenes. lukemia frowardly kapgnger146: outpiping, " ascii
        $s5 = "ere lykkedrms? provincialship: tha204 nosegay: staffing, unmalleableness; multicellular139 baksendes" ascii
        $s6 = "Rem Trretumbler; horologium238. fenton; stridsskrifternes! sanguinarily197 cenacle wisewomen, torsha" ascii
        $s7 = "! uninvitedly96 pyrrhonism geotropic; kinorhyncha63 indbanknings vaabenhvile: polygala; palazzos198 " ascii
        $s8 = "malaja economy201: metrists. grif chankings avisudviklingernes238: knapped92 tolkningsrammer strejfk" ascii
        $s9 = "Rem Dictyopteran117 kvikslv170. meteorite skihoppernes; skovmands? uopdragelig: studier! disheveling" ascii
        $s10 = "n. vejrmeldingens reassociating hutkeeper! bibliopolar: hypogamy227, suckless obverting; kellys. skj" ascii
        $s11 = "es myzostomidae? boutiquen, phoenicochroite iarovizing205? brackmard? svlgende, slounger. telefonvse" ascii
    condition:
        filesize < 1048576 and 12 of them
}

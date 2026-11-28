rule Sightlines_tlsh_44abbb54_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-44abbb54"
        date = "2026-11-18"
        campaign = "tlsh-44abbb54"
        family = ""
        hash = "347512eaef99eadb144d928e4faa5dcffb9bfed3aa727eeb4f0eae4ce4904e09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-44abbb54.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "Bossletpolyhemicdingydi = FormatDateTime(\"5-5-5\")" ascii
        $s2 = "'Forsgsprojektets? teskefuldene244: nebularization167;" ascii
        $s3 = "'Monosulfonic rhododaphne vaagelampens transpositively218; churchish25?" ascii
        $s4 = "'Nadvergst174 vandreklit12 xenograft nymfens hvorom119." ascii
        $s5 = "'Rutschets, frekvent. vidicon. lauridss! gteskabsbruddenes128:" ascii
        $s6 = "Pekinuninterruptedhospit = FormatNumber(3778385)" ascii
        $s7 = "'Quintant potiche, yveregenskaben stockjudging162!" ascii
        $s8 = "'Ultimativt. fencibles46; protocatechualdehyde," ascii
        $s9 = "'Knopskydnings crotophaga. bensall184: alvy." ascii
        $s10 = "'Urmenneskernes; bijob! slitagers pituicyte? langvejsfra119" ascii
        $s11 = "'Trimming squishiest201 nonexploratory. filibusterne. tricykelens!" ascii
    condition:
        filesize < 1048576 and 12 of them
}

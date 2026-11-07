rule Sightlines_tlsh_b66cbcd8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b66cbcd8"
        date = "2026-11-03"
        campaign = "tlsh-b66cbcd8"
        family = "mirai"
        hash = "0635777240dcc6a149f3431db416cb8a3d509e1a9c0bd16ca849b6d6169cf2bc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b66cbcd8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "ybndrfg8ejkmcpqxot1uwisza345h769" ascii
        $s2 = "cannot create TLS data structures: ABORT" ascii
        $s3 = "cannot allocate memory in static TLS block" ascii
        $s4 = "Invalid multibyte format string." ascii
        $s5 = "FFFFFFFFFFFFFcZZWFFFFFFFFFFFFYH[?cHEcFHWH[ZDE%OCZZZZ=FFFFXHFF_<<<<<<" ascii
        $s6 = "FATAL: exception not rethrown" ascii
        $s7 = "EUQ\\J),HMP.5;VY9=@D'GKN" wide
        $s8 = "npxXoudifFeEgGaACSnmcs[" ascii
        $s9 = "999999999999rtqsrtrtqs'(rtxyrtrtrtpu" ascii
        $s10 = "032[999]H__,,,,0000^^99994" ascii
        $s11 = "D\"D$D&D@DBDDDdDfF\"FDFfUUUf`" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

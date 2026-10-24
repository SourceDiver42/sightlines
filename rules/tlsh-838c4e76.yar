rule Sightlines_tlsh_838c4e76_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-838c4e76"
        date = "2026-10-22"
        campaign = "tlsh-838c4e76"
        family = "mirai"
        hash = "1b40941c18e456f93a1bbce6c440fae0b3c281cd56a527680f93cc088288e50c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-838c4e76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "cn3,73a~41+Cg)A(G{!" ascii
        $s2 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
        $s3 = "/etc/config/hosts" ascii
        $s4 = "qQSRVSWTXUYVZW[" ascii
        $s5 = "FhFiFjFkFlFmFnFo&D" ascii
        $s6 = "R36al13`x!3b" ascii
        $s7 = "6Cg*7casb@2" ascii
        $s8 = "BcAR2a3f&g" ascii
        $s9 = "/ci\"OEQb1" ascii
        $s10 = "F@aChPbSg" ascii
        $s11 = "9'SdPa 1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

rule Sightlines_tlsh_1927bb3a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1927bb3a"
        date = "2026-11-03"
        campaign = "tlsh-1927bb3a"
        family = "mirai"
        hash = "1f6bf76318997e432a2d4fc7ef72d1026616e97b9ee348f3f07deb83c8d23241"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1927bb3a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "3ba48c8fc99fe60a8e00e11f96ae6f3ceddee362443b2de85221bca121b2bca62e87494704555d2e776bea3a214a8517" ascii
        $s1 = "22bcc89516fc6eb00a9d218fb4e3535bea535d1746aa216c8362c818d571a4ef" ascii
        $s2 = "3aae4cd9f22a3a8973dca69820b63dedc60b5704efc047317bde5bd0c093618b" ascii
        $s3 = "462ed0ca19a2a242c888359ab5dd13c9947a7f07dee87f6c90ec3b01f1492cca" ascii
        $s4 = "848e43671490fd10be19a793e3122be0244fa8542affacdb7ec56e2726169c14" ascii
        $s5 = "6c23c9b4f83d37fedcee506c28f743f1b17964a27d299bd1ce4c76715e50151f" ascii
        $s6 = "5de7c8f5a495d71db82258bad213deabd6fe2972ca7794931c6f77ffd9600870a6c700ed6a6c151d653c1d9c0f169f7e" ascii
        $s7 = "bed6aaed9f9aa3ece7c3f66be4c83ba10ff43b0f9095d7110421fd6605550986" ascii
        $s8 = "9f1092510dcccdb5874175e1f681bd6abf5863ccd6b219eb4eef748c18640354" ascii
        $s9 = "d25076cc6471cb0f7bd7204e7390ba2ea147cb6eb53b018d9618d34967148d29" ascii
        $s10 = "a29a1a318af843dedafaabee63660f90152737745e636109046e1ecbb65ab48c" ascii
        $s11 = "39bca43c052af88c001e810dac1897e3c66b41a861b346c90d4045fbcf8924dd" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

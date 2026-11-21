rule Sightlines_tlsh_d0cfff71_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d0cfff71"
        date = "2026-11-20"
        campaign = "tlsh-d0cfff71"
        family = "mirai"
        hash = "a7b523609fe8cc5cecb3ccfeed3864d6865884c2407eff3e4c6ab39b52292b76"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d0cfff71.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "[0clKillerStat] Killed Process: %s, PID: %d" ascii
        $s2 = "[0clKillerMaps] Killed Process: %s, PID: %d" ascii
        $s3 = "[0clKillerKillerEXE] Killed process: %s, PID: %d" ascii
        $s4 = "3aae4cd9f22a3a8973dca69820b63dedc60b5704efc047317bde5bd0c093618b" ascii
        $s5 = "bed6aaed9f9aa3ece7c3f66be4c83ba10ff43b0f9095d7110421fd6605550986" ascii
        $s6 = "d25076cc6471cb0f7bd7204e7390ba2ea147cb6eb53b018d9618d34967148d29" ascii
        $s7 = "a29a1a318af843dedafaabee63660f90152737745e636109046e1ecbb65ab48c" ascii
        $s8 = "39bca43c052af88c001e810dac1897e3c66b41a861b346c90d4045fbcf8924dd" ascii
        $s9 = "03754966d64a3cc3173e1b56c45e7404668b8310e9fbdacaa07bfcd10b7a8081" ascii
        $s10 = "27707a49472c8d6a0a889c77081096fefeb8a7b53157180983b1f4b7fc3bd7bb" ascii
        $s11 = "b43ed9347ff372c00bb33e297f71c6e499e52d13d70f7ca8d21d39f256dd5d7f" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}

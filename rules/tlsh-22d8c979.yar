rule Sightlines_tlsh_22d8c979_wardenstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-22d8c979"
        date = "2026-11-11"
        campaign = "tlsh-22d8c979"
        family = "wardenstealer"
        hash = "05d377c8263e20008aca7bcd0f9b9187d2c70599fdfec334bb6bbfb03e52ebd4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-22d8c979.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\" (FormatMessageW() returned error " ascii
        $s1 = "GetSystemDefaultLangID" ascii
        $s2 = "D$ H3L$ H3" ascii
        $s3 = "build.pdb" ascii
        $s4 = "AVVWUSE1" ascii
        $s5 = "OS Error " ascii
        $s6 = "build.dll" ascii
        $s7 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171456 and 3 of them
}

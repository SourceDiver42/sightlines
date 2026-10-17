rule Sightlines_tlsh_63f610dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-63f610dc"
        date = "2026-10-17"
        campaign = "tlsh-63f610dc"
        family = ""
        hash = "082ae04ff9306111505f1fcdbef1aca226d2c02f05cd4300374fa64f58a99778"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-63f610dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\" (FormatMessageW() returned error " ascii
        $s1 = "AWAVVWUSPH" ascii
        $s2 = "D$ H3L$ H3" ascii
        $s3 = "AVVWUSE1" ascii
        $s4 = "OS Error " ascii
        $s5 = "L$HH1D$ " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1327104 and 5 of them
}

rule Sightlines_tlsh_a15f04b4_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a15f04b4"
        date = "2026-11-23"
        campaign = "tlsh-a15f04b4"
        family = "revstealer"
        hash = "6c705d296e0fe83d0435a5d5c22152c2efeebc1c49c8a35846118834958fb229"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a15f04b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "H9A8uBH9APu<H9Ahu6H9" ascii
        $s1 = "L9d$Xu7L9d$pu0L9e" ascii
        $s2 = "t,fD9(t&fD9+t" ascii
        $s3 = "thfD9(tbfD9+t" ascii
        $s4 = "twD9t$PvpHc" ascii
        $s5 = "t}D9l$0vvIc" ascii
        $s6 = "ucfD9t$0t[H" ascii
        $s7 = "x_fD9D$`tWH" ascii
        $s8 = "L9t$@u{L97H" ascii
        $s9 = "\\$hfD93t6H" ascii
        $s10 = "\\$pfD93t6H" ascii
        $s11 = "sWfD9cHv;L" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

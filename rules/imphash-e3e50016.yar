rule Sightlines_imphash_e3e50016_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e3e50016"
        date = "2026-11-06"
        campaign = "imphash-e3e50016"
        family = "revstealer"
        hash = "2485c93e1e4aff8cdc24074d1992d0d6a55c14d24d71d2dbd1ddbe9f077377f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e3e50016.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShellAboutW" ascii
        $s1 = "[+NCSPyx" ascii
        $s2 = "xIN>]-fQ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9522176 and 3 of them
}

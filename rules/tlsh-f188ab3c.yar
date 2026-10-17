rule Sightlines_tlsh_f188ab3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f188ab3c"
        date = "2026-10-15"
        campaign = "tlsh-f188ab3c"
        family = ""
        hash = "17d63275d00bdd8670422b95bd264c532998e0a1b041079e54fce4b6b7a55819"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f188ab3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

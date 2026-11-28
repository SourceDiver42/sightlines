rule Sightlines_tlsh_a996e388_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a996e388"
        date = "2026-11-26"
        campaign = "tlsh-a996e388"
        family = "remcos"
        hash = "0aa6ce489af25425df679df31af8c71a73ee193826266daa4ec68be704c0c094"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a996e388.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    If Err.Number = 0 Then" ascii
        $s1 = "        On Error Resume Next" ascii
        $s2 = "    On Error GoTo 0" ascii
        $s3 = "Option Explicit" ascii
        $s4 = "    Randomize" ascii
    condition:
        filesize < 6870020 and 5 of them
}

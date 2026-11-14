rule Sightlines_tlsh_a996e388_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a996e388"
        date = "2026-11-13"
        campaign = "tlsh-a996e388"
        family = "remcos"
        hash = "84dfb09549ea2d5dddd5c078660d39587307290525a131801a70c4310494c743"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a996e388.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "dXJlIExvYWRlciAtIEFkdmFuY2VkIERlY3J5cHRpb24gRW5naW5lDQojPT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09" ascii
        $s1 = "    If Err.Number = 0 Then" ascii
        $s2 = "        On Error Resume Next" ascii
        $s3 = "    On Error GoTo 0" ascii
        $s4 = "Option Explicit" ascii
        $s5 = "    Randomize" ascii
    condition:
        filesize < 6875662 and 5 of them
}

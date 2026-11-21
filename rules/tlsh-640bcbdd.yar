rule Sightlines_tlsh_640bcbdd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-640bcbdd"
        date = "2026-11-03"
        campaign = "tlsh-640bcbdd"
        family = ""
        hash = "a692fb942dd967e142e1b47e49b5d1a0216e0f5ee1cb387b8567117875705a75"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-640bcbdd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ElseIf False Then" ascii
        $s1 = "If Not True Then" ascii
        $s2 = "    Exit Function" ascii
        $s3 = "     End Function" ascii
        $s4 = "Do While False" ascii
        $s5 = "Select Case 10" ascii
        $s6 = "Select Case 12" ascii
        $s7 = "Select Case 13" ascii
        $s8 = "Select Case 14" ascii
        $s9 = "Select Case 15" ascii
        $s10 = "Select Case 16" ascii
        $s11 = "Select Case 17" ascii
    condition:
        filesize < 17524554 and 12 of them
}

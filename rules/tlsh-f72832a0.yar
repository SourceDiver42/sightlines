rule Sightlines_tlsh_f72832a0_masslogger
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f72832a0"
        date = "2026-11-24"
        campaign = "tlsh-f72832a0"
        family = "masslogger"
        hash = "2162d118e24e8a6733a0a64c3117b497a53bdb3eea021db4009a09883457cb1e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f72832a0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        Emit \"DECODE_ERR: \" & Err.Description" ascii
        $s1 = "    If Err.Number = 0 Then" ascii
        $s2 = "        On Error Resume Next" ascii
        $s3 = "    On Error GoTo 0" ascii
        $s4 = "Option Explicit" ascii
        $s5 = "    Randomize" ascii
    condition:
        filesize < 1412634 and 5 of them
}

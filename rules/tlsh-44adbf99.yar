rule Sightlines_tlsh_44adbf99_grandoreiro
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-44adbf99"
        date = "2026-11-11"
        campaign = "tlsh-44adbf99"
        family = "grandoreiro"
        hash = "039851fe0310d0e281fe0068ebe546dfaef34838bd506fd341bd4e71a8cf1530"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-44adbf99.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "On Error Resume Next" ascii
        $s1 = "On Error GoTo 0" ascii
        $s2 = "WScript.Quit" ascii
        $s3 = "AAAAAAAAAABAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAE" ascii
        $s4 = "BAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAARAEAAAAAAAAAA" ascii
    condition:
        filesize < 9325504 and 4 of them
}

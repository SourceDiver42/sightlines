rule Sightlines_tlsh_77fef818_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-77fef818"
        date = "2026-11-19"
        campaign = "tlsh-77fef818"
        family = ""
        hash = "05e2208e78605e631d331f14450cbf09acadcabdfc6b6bf566e5ef693fd15953"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-77fef818.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "if ([System.Environment]::Is64BitProcess)" ascii
        $s1 = "[System.IO.Pipes.PipeOptions]::None);" ascii
        $s2 = "[Parameter( Position = 1 )]" ascii
        $s3 = "[Parameter( Position = 0)]" ascii
        $s4 = "[OutputType([Type])]" ascii
        $s5 = "return $null;" ascii
        $s6 = "} finally {" ascii
        $s7 = "    return" ascii
        $s8 = "catch {}" ascii
    condition:
        filesize < 1412852 and 9 of them
}

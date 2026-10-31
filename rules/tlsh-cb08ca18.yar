rule Sightlines_tlsh_cb08ca18_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cb08ca18"
        date = "2026-10-30"
        campaign = "tlsh-cb08ca18"
        family = ""
        hash = "07e99db7ab005170ff163313fc4b03b278c0dc072f916cb0b5a19faef3d4860a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cb08ca18.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AWAVAUATVWUSPI" ascii
        $s1 = "AWAVAUATVWUSI" ascii
        $s2 = "AWAVATVWUSI" ascii
        $s3 = "UAWAVVWSPH" ascii
        $s4 = "AWAVVWUSI" ascii
        $s5 = "AWAVVWSI" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4180992 and 6 of them
}

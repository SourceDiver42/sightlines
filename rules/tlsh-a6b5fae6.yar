rule Sightlines_tlsh_a6b5fae6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a6b5fae6"
        date = "2026-11-02"
        campaign = "tlsh-a6b5fae6"
        family = ""
        hash = "6246f5fe726fbf612ca621961fd90a440425d64e9f4e51b7bb7adb80651032fa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a6b5fae6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[conn][%1] Received APPLICATION_ERROR error, delaying close in expectation of a 1-RTT CONNECTION_CLO" wide
        $s1 = "[sett] StreamMultiReceiveEnabled  = %hhu" ascii
        $s2 = "[sett] StreamMultiReceiveEnabled= %hhu" ascii
        $s3 = "SE frame." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1074800 and 4 of them
}

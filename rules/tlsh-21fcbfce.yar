rule Sightlines_tlsh_21fcbfce_silentnet
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21fcbfce"
        date = "2026-11-16"
        campaign = "tlsh-21fcbfce"
        family = "silentnet"
        hash = "540024573df28f7258f5d03c97dcc35aa02cdf242eef564c6d503037706622ad"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21fcbfce.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "assets/pulsescanner/textures/tiers/mctiers/PK" ascii
        $s1 = "assets/pulsescanner/textures/tiers/subtiers/PK" ascii
        $s2 = "assets/pulsescanner/textures/tiers/tierlists/PK" ascii
        $s3 = "assets/pulsescanner/textures/tiers/PK" ascii
        $s4 = "assets/pulsescanner/shaders/core/PK" ascii
        $s5 = "XxDxTxLx\\xBxRxJX\"<m\\d\\l\\b\\j\\f\\.,7" ascii
        $s6 = "assets/pulsescanner/textures/PK" ascii
        $s7 = "assets/pulsescanner/shaders/PK" ascii
        $s8 = "assets/pulsescanner/media/PK" ascii
        $s9 = "pulsescanner.accesswidenerPK" ascii
        $s10 = "pulsescanner.mixins.jsonPK" ascii
        $s11 = "assets/pulsescanner/font/PK" ascii
    condition:
        filesize < 4607826 and 12 of them
}

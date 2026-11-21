rule Sightlines_c2_16a44147_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-16a44147"
        date = "2026-11-16"
        campaign = "c2-16a44147"
        family = ""
        hash = "0aa8242036727ce927b30e2d1c8e50072be9dc157093ca171961f07e0c13e3cd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-16a44147.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "After=network.target" ascii
        $s1 = "Restart=always" ascii
        $s2 = "RestartSec=10" ascii
        $s3 = "#!/bin/bash" ascii
        $s4 = "[Service]" ascii
    condition:
        filesize < 1048576 and 5 of them
}

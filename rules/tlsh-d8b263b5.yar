rule Sightlines_tlsh_d8b263b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d8b263b5"
        date = "2026-11-21"
        campaign = "tlsh-d8b263b5"
        family = ""
        hash = "01782f383fb78aad98ccafc5db9b41b427399b0c1e3929cf63b884d36c716753"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d8b263b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    # Uncomment this block if needed" ascii
        $s1 = "ARCH=$(uname -m)" ascii
        $s2 = "    threads=75" ascii
        $s3 = "dir=$(pwd)" ascii
    condition:
        filesize < 1048576 and 4 of them
}

rule Sightlines_tlsh_b634159d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b634159d"
        date = "2026-11-22"
        campaign = "tlsh-b634159d"
        family = ""
        hash = "0c693dc44a0430325c1df18c7b4e9cbb9bdefbe60902d35a65650f4c1ed03d4a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b634159d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "                if (Array.isArray(data)) throw new Error('stamp path is a directory');" ascii
        $s1 = "        uses: actions/github-script@v7" ascii
        $s2 = "  cancel-in-progress: false" ascii
        $s3 = "  workflow_dispatch:" ascii
        $s4 = "      contents: write" ascii
        $s5 = "  group: auto-bump" ascii
        $s6 = "    permissions:" ascii
        $s7 = "concurrency:" ascii
        $s8 = "  schedule:" ascii
    condition:
        filesize < 1048576 and 9 of them
}

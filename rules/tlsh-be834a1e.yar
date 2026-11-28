rule Sightlines_tlsh_be834a1e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be834a1e"
        date = "2026-11-27"
        campaign = "tlsh-be834a1e"
        family = ""
        hash = "0425643406699d9cc2b324b57159a7c47e764cbcb675fb726c7c848368e7566e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be834a1e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" ascii
        $s1 = "%ProgramFiles(x86)%\\Microsoft\\Edge\\Application\\msedge.exe" ascii
        $s2 = "@shell32.dll,-21817" wide
        $s3 = "MICROS~1" ascii
        $s4 = "APPLIC~1" ascii
        $s5 = "PROGRA~2" ascii
    condition:
        filesize < 1048576 and 6 of them
}

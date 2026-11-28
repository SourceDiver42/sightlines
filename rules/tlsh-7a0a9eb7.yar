rule Sightlines_tlsh_7a0a9eb7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7a0a9eb7"
        date = "2026-11-15"
        campaign = "tlsh-7a0a9eb7"
        family = ""
        hash = "0849b3bf75c35be042dff76ce530e2f153b649a1202f50d575238648f2bde4ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7a0a9eb7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "380114235959Z0i1" ascii
        $s1 = "Full Version" wide
        $s2 = "250507000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}

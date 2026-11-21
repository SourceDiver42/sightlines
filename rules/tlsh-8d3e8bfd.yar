rule Sightlines_tlsh_8d3e8bfd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8d3e8bfd"
        date = "2026-11-19"
        campaign = "tlsh-8d3e8bfd"
        family = ""
        hash = "00110ce22687b3ea3b36a95841909f4c0f1d1a0288206499c2e15de8ea349be4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8d3e8bfd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bi'+'le'+'Ap'+'p'](!0x0)}\">Try this alternate link</span></wcm-text>`:null}</wcm-info-footer><wcm-in" ascii
        $s1 = "ary\" variant=\"small-thin\">Still doesn't work? <span tabindex=\"0\" @click=\"${()=>this['op'+'en'+'Mo'+'" ascii
        $s2 = "\" .isError=\"${this['is'+'Er'+'ro'+'r']}\"></wcm-connector-waiting></wcm-modal-content><wcm-info-foote" ascii
    condition:
        filesize < 6729470 and 3 of them
}

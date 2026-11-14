rule Sightlines_tlsh_c0892a22_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0892a22"
        date = "2026-11-13"
        campaign = "tlsh-c0892a22"
        family = ""
        hash = "50774628062fd31b15c9873660cf033e457d5b88001de1a3a2779f800b6ba16b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0892a22.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "juze ku. E_osyefn" ascii
        $s1 = "N0ZNFD8-0B55AEDC3" ascii
        $s2 = "pekbe.Aj-sip*w(" ascii
        $s3 = "Bikebpa_duxi de" ascii
        $s4 = "713}N68D56E05-" ascii
        $s5 = "hd-t~dtvij<ag-" ascii
        $s6 = "^$po_eqeliw6A" ascii
        $s7 = "Luwpuvuy_for&" ascii
        $s8 = " h3GdZ*|Q8yK" ascii
        $s9 = "(4'@y2!OLPXh" ascii
        $s10 = "yg'PtAwnlTqy" ascii
        $s11 = "VJtH7;ZY8l08" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}

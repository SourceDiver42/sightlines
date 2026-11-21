rule Sightlines_imphash_9bcbcf12_stealc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9bcbcf12"
        date = "2026-11-10"
        campaign = "imphash-9bcbcf12"
        family = "stealc"
        hash = "044080f017f38a21eb4a560aff3c97c30f375144940fe312ad85bc9014e53792"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9bcbcf12.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ" ascii
        $s1 = ".?AV?$basic_istringstream@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@" ascii
        $s2 = "\\BraveSoftware\\Brave-Browser\\User Data\\Local State" ascii
        $s3 = "\\Microsoft\\Edge\\User Data\\Local State" ascii
        $s4 = "\\Google\\Chrome\\User Data\\Local State" ascii
        $s5 = "unescaped control character in string" ascii
        $s6 = "JSON number is out of int64 range" ascii
        $s7 = "operator[] requires a JSON object" ascii
        $s8 = ".?AU_Ctype_constants_base@std@@" ascii
        $s9 = "JSON number is out of int range" ascii
        $s10 = "only utf-8 sqlite is supported" ascii
        $s11 = ".?AVJsonOutOfRange@gatejson@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1276928 and 12 of them
}

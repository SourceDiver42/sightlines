rule Sightlines_imphash_9bcbcf12_stealc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9bcbcf12"
        date = "2026-11-02"
        campaign = "imphash-9bcbcf12"
        family = "stealc"
        hash = "3bb5bf520eb23961d31d5af97d67bea6fff6e111c96eac490044c5b9720a04af"
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
        uint16(0) == 0x5A4D and filesize < 1275904 and 12 of them
}

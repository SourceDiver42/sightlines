rule Sightlines_tlsh_10248e78_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-10248e78"
        date = "2026-11-13"
        campaign = "tlsh-10248e78"
        family = ""
        hash = "0e2ef965c9741b97004fb8d56e5f61596dcceed64da3164f03b7071bd30be63c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-10248e78.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "RegExPatternsDropDownList.DefaultModifiers" wide
        $s2 = "]Regular Expression Pattern to use for validation.  See accompanied regular expression bank..." ascii
        $s3 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s4 = "lType of comparison to perform with ValueToCompare.  Default is data type checking if DataType is no" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "2Message to display/return iwhen validation failed." ascii
        $s7 = "AI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchestr" wide
        $s8 = "_Highest value the control can have.  Remember to set DataType when range is not of type String." ascii
        $s9 = "<Case sensitivity validation works best with String DataType." ascii
        $s10 = "iAI-driven multi-domain data validation and integrity assurance framework with adaptive rule orchest" ascii
        $s11 = "^Lowest value the control can have.  Remember to set DataType when range is not of type String." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1618944 and 12 of them
}

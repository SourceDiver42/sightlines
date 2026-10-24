rule Sightlines_rich_header_hash_2a6cf275_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-2a6cf275"
        date = "2026-10-22"
        campaign = "rich_header_hash-2a6cf275"
        family = ""
        hash = "16c31ad3c6f484a172280b83c15d81e5062cf504444d13af7af3e31ab7a96bae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-2a6cf275.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s1 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s2 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s3 = "Installer integrity check has failed. Common causes include" wide
        $s4 = "Error writing temporary file. Make sure your temp folder is valid." wide
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion" wide
        $s6 = "installer's author to obtain a new copy." wide
        $s7 = "incomplete download and damaged media. Contact the" wide
        $s8 = ".DEFAULT\\Control Panel\\International" wide
        $s9 = "Control Panel\\Desktop\\ResourceLocale" wide
        $s10 = "http://nsis.sf.net/NSIS_Error" wide
        $s11 = "verifying installer: %d%%" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 12792758 and 12 of them
}

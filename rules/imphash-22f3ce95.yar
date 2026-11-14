rule Sightlines_imphash_22f3ce95_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-22f3ce95"
        date = "2026-11-10"
        campaign = "imphash-22f3ce95"
        family = ""
        hash = "456224488bd4f9be1a233cce6c028452d8950ead6763b97c52f33fb1cbf1f3cc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-22f3ce95.json"
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
        $s9 = "Please wait while Setup is loading..." wide
        $s10 = "Control Panel\\Desktop\\ResourceLocale" wide
        $s11 = "http://nsis.sf.net/NSIS_Error" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1233136 and 12 of them
}

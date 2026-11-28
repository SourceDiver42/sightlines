rule Sightlines_imphash_65453c65_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-65453c65"
        date = "2026-11-10"
        campaign = "imphash-65453c65"
        family = ""
        hash = "364e30dee55cd79a5ba9ce59b01855091da757c8141a76552f0b67f46b410fb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-65453c65.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "soft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v3.08</description><dependency" ascii
        $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s2 = "mbly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges" ascii
        $s3 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s4 = "><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=" ascii
        $s5 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s6 = "Installer integrity check has failed. Common causes include" wide
        $s7 = "Error writing temporary file. Make sure your temp folder is valid." wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion" wide
        $s9 = "installer's author to obtain a new copy." wide
        $s10 = "incomplete download and damaged media. Contact the" wide
        $s11 = ".DEFAULT\\Control Panel\\International" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3936352 and 12 of them
}

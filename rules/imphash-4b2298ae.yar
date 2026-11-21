rule Sightlines_imphash_4b2298ae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4b2298ae"
        date = "2026-11-12"
        campaign = "imphash-4b2298ae"
        family = ""
        hash = "56ebb217ecff17661030676747fb1fea2b20f5cda09bc8d9ffcdf683d98e4fd0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4b2298ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "llsoft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v2.37</description><dependen" ascii
        $s1 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s2 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nu" ascii
        $s3 = "cy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" versio" ascii
        $s4 = "RMDir: RemoveDirectory invalid input(\"%s\")" ascii
        $s5 = "File: overwriteflag=%d, allowskipfilesflag=%d, name=\"%s\"" ascii
        $s6 = "ExecShell: warning: error (\"%s\": file:\"%s\" params:\"%s\")=%d" ascii
        $s7 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
        $s8 = "IfFileExists: file \"%s\" does not exist, jumping %d" ascii
        $s9 = "Installer integrity check has failed. Common causes include" ascii
        $s10 = "IfFileExists: file \"%s\" exists, jumping %d" ascii
        $s11 = "File: skipped: \"%s\" (overwriteflag=%d)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 19897356 and 12 of them
}

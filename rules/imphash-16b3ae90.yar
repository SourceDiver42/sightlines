rule Sightlines_imphash_16b3ae90_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-16b3ae90"
        date = "2026-11-13"
        campaign = "imphash-16b3ae90"
        family = ""
        hash = "1a9c85046db6983f741c7706861c4080762ec7059df38f0522ace6f7e36cac55"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-16b3ae90.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1.4.0.1794\" name=\"7-Zip.SfxMod\" type=\"win32\"></assemblyIdentity><dependency><dependentAssembly><asse" ascii
        $s1 = "mblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" processorArchit" ascii
        $s2 = "trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutio" ascii
        $s3 = "1.4.0 beta [x86] build 1795 (June 27, 2010)" ascii
        $s4 = "nLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security" ascii
        $s5 = "Copyright (c) 2005-2010 Oleg Scherbakov" ascii
        $s6 = "Sorry, this program requires Microsoft Windows 2000 or later." ascii
        $s7 = "No \"HelpText\" in the configuration file." ascii
        $s8 = "ExtractPathTitle=\"7-ZIP SFX archive\"" ascii
        $s9 = "ExtractPathText=\"Select extraction path\"" ascii
        $s10 = "Could not read SFX configuration or configuration not found." ascii
        $s11 = "7-Zip: Internal error, code 0x%08X." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 36015060 and 12 of them
}

rule Sightlines_imphash_086887b8_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-086887b8"
        date = "2026-11-12"
        campaign = "imphash-086887b8"
        family = "coinminer"
        hash = "0471e31583e0c84eb96463cb68e4395e1b36e63d5d55c8d92c936557e569e7c2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-086887b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s1 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"X86\" name=\"Nu" ascii
        $s2 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
        $s3 = "Error writing temporary file. Make sure your temp folder is valid." ascii
        $s4 = "Software\\Microsoft\\Windows\\CurrentVersion" ascii
        $s5 = ".DEFAULT\\Control Panel\\International" ascii
        $s6 = "verifying installer: %d%%" ascii
        $s7 = "WritePrivateProfileStringA" ascii
        $s8 = "Error launching installer" ascii
        $s9 = "GetPrivateProfileStringA" ascii
        $s10 = "GetDiskFreeSpaceExA" ascii
        $s11 = "SeShutdownPrivilege" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7104336 and 12 of them
}

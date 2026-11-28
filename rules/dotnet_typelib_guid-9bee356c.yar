rule Sightlines_dotnet_typelib_guid_9bee356c_stealeriumstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9bee356c"
        date = "2026-11-27"
        campaign = "dotnet_typelib_guid-9bee356c"
        family = "stealeriumstealer"
        hash = "51f242dc0ead83cd647df9038aad2184455df243f66c4e842ddd73b4b16cf6e9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9bee356c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "icKeyToken=cc7b13ffcd2ddd51|System.Buffers.dll|2F410A0396BC148ED533AD49B6415FB58DD4D641|20856" ascii
        $s2 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s3 = "costura.dotnetzip.pdb.compressed|||DotNetZip.pdb|565BABCBCD978AF66FE1150CC58FDEAFC9815822|622080" ascii
        $s4 = "KeyToken=cc7b13ffcd2ddd51|System.Memory.dll|19BF79600B716523B5317B9A7B68760AE5D55741|141184" ascii
        $s5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s6 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s7 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s8 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s9 = "SELECT * FROM Win32_PnPEntity WHERE (PNPClass = 'Image' OR PNPClass = 'Camera')" wide
        $s10 = "costura.costura.pdb.compressed|||Costura.pdb|6C6000A5EAF8579850AB82A89BD6268776EB51AD|2608" ascii
        $s11 = "\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\cjmkndjhnagcfbpiemnkdpomccnjblmj" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3178496 and 12 of them
}

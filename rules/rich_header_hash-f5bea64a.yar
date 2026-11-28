rule Sightlines_rich_header_hash_f5bea64a_purerat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-f5bea64a"
        date = "2026-11-11"
        campaign = "rich_header_hash-f5bea64a"
        family = "purerat"
        hash = "1f397e72dceb75d8d70c991a08176f4734c7cb431cad853b7d9165783a04ade3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-f5bea64a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "ConvertInterfaceNameToLuidW" ascii
        $s4 = "V8*,8D18Y\"M" ascii
        $s5 = "T!BIBn@#bM" ascii
        $s6 = "I4]20l&,N" ascii
        $s7 = "4$2<.68i" ascii
        $s8 = "HB3L.I\\x" ascii
        $s9 = "tm3}W7xJ" ascii
        $s10 = "{Y2p]OmT" ascii
        $s11 = "+1535-k," ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7677008 and 11 of them
}

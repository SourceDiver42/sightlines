rule Sightlines_tlsh_808e579c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-808e579c"
        date = "2026-11-10"
        campaign = "tlsh-808e579c"
        family = ""
        hash = "12e7d0792c32071503466696fb7cd187d0b36e4f23e6df9a2182e15a9b66be1f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-808e579c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "get_Action_Close_32x32" ascii
        $s4 = "Add;Plus;Bars;Ribbon;" ascii
        $s5 = ".NET Framework 4.5" ascii
        $s6 = "get_Edit_32x32" ascii
        $s7 = "get_Add_32x32" ascii
        $s8 = "50a3aPADPADC" ascii
        $s9 = "Copyright " ascii
        $s10 = "get_OPlus" ascii
        $s11 = "tEXtTitle" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1608704 and 11 of them
}
